import { Principal } from '@icp-sdk/core/principal';
import { IdbKeyVal } from './db.js';
import { Doorbell, readOnlyError, STATE_DB, withLock } from './local-state-storage.js';
import { LocalStorageCopy, type SessionState, type StateStorage } from './state-storage.js';

/** The channel a tab announces a new answer on, for the workers of its origin. */
const ANSWER_CHANNEL = 'ic-session-answer';

/** Where a tab keeps its answer for the workers of its origin. */
const answerKey = (key: string): string => `${key}#answer`;

/** One answer in IndexedDB: what {@link stateOf} gives, or `null` for none. */
interface StoredAnswer {
  raw: string | null;
}

const isAnnouncement = (value: unknown): value is { key: string } =>
  typeof value === 'object' &&
  value !== null &&
  typeof (value as { key?: unknown }).key === 'string';

/**
 * How long the browser keeps the record, which is not how long the sign-in
 * lasts: the record says when the session expires, and it is kept past that so
 * every sibling can say the session ended rather than that nobody signed in.
 * Signing in rewrites it and signing out removes it, so this is only the
 * ceiling on a record nothing came back for.
 *
 * Four hundred days because that is what browsers allow — Chrome, Edge and
 * Firefox cap a persistent cookie there and silently truncate anything longer.
 * Safari caps a cookie written by script to seven days, which shortens this
 * without breaking it: the record lapses to signed out, the same answer a
 * cleared store gives.
 */
const RECORD_MAX_AGE_SECONDS = 400 * 24 * 60 * 60;

/**
 * Whether a hostname is loopback, which browsers treat as a secure context, so a
 * cookie set there needs no `Secure` attribute.
 */
const isLoopbackHost = (hostname: string): boolean =>
  hostname === 'localhost' ||
  hostname.endsWith('.localhost') ||
  hostname === '127.0.0.1' ||
  hostname === '[::1]';

export interface CookieStateStorageOptions {
  /**
   * Domain to scope the cookie to, e.g. `example.com` so `a.example.com` and
   * `b.example.com` share one sign-in.
   *
   * Must be the current host or a domain above it: the browser rejects a cookie
   * scoped to anything else, including a sibling subdomain, and refuses a public
   * suffix — so an over-broad value fails rather than leaking to unrelated sites.
   * Nothing needs to be served at the domain; it is only a scope.
   */
  domain: string;
}

/**
 * The state of a sign-in, in a cookie, so every sibling of a domain shares it.
 *
 * A cookie is the only thing that crosses between origins, which is what lets one
 * sign-out end them all: the record is the domain's rather than this origin's, so
 * removing it is what tells a sibling the sign-in is over. It carries no chain
 * and no key, so a sibling acting on it asks the identity provider to re-issue
 * rather than treating it as proof.
 *
 * Workers cannot read cookies, so each tab keeps its whole answer (who is signed
 * in, until when, and whether this origin holds it) in IndexedDB as one record,
 * and a worker reads that. One record, so a worker never sees half of a change.
 * Workers only read: signing in and out happens in a page. A service worker
 * running with no page of its origin open sees a sibling's change once a page of
 * its origin next reads the cookie.
 * @see implements {@link StateStorage}
 */
export class CookieStateStorage implements StateStorage {
  /**
   * A sign-in kept here may be resumed without a ceremony.
   *
   * This is the store whose record reaches past one origin, so it is the store
   * whose siblings arrive holding no credential and needing the identity
   * provider to remember the session they can be given one from. Asking a
   * provider to keep a sign-in is only worth the persistence where somebody is
   * going to come back to it, and here somebody will.
   */
  public readonly resumable = true;

  /** True in a worker, which reads the answer the tabs of its origin publish. */
  public readonly isReadOnly = typeof document === 'undefined';

  readonly #attributes: string;
  #subscribers = new Map<string, Set<() => void>>();

  // The cookie is the domain's and says who is signed in; this says whether it
  // was this origin that acquired a credential for them. A cookie cannot carry
  // that (every sibling reads the same bytes), so it is kept per origin and
  // composed in on read, under the same key the cookie uses.
  readonly #claim = new LocalStorageCopy();

  // Writes in progress. set() and remove() each change the claim and the cookie,
  // and a subscriber told between the two would see, and could act on, a state
  // that was never meant to exist. Subscribers are told once both have landed.
  #writeDepth = 0;

  // In a tab: the answer last published for each key.
  readonly #published = new Map<string, string>();

  // In a worker: the answers loaded from IndexedDB, and what keeps them current.
  readonly #answers = new Map<string, SessionState | null>();
  readonly #loadedKeys = new Set<string>();
  readonly #versions = new Map<string, number>();
  readonly #pendingLoads = new Set<Promise<void>>();
  readonly #doorbell = new Doorbell(ANSWER_CHANNEL, (data) => this.#receive(data));
  #subscriberCount = 0;

  constructor(options: CookieStateStorageOptions) {
    // Both sides, because this decides whether to skip the check below and drop
    // the `Domain` attribute. Taken from the configured domain alone, a
    // `domain: 'localhost'` on a real host would do both — accept the
    // misconfiguration and write a host-only cookie — which is the silent
    // failure the check exists to prevent.
    const hostname = globalThis.location?.hostname;
    const loopback =
      isLoopbackHost(options.domain) && (hostname === undefined || isLoopbackHost(hostname));

    // A browser silently ignores `document.cookie` when the domain is not this
    // host or one above it, and this cookie is the state itself, so the sign-in
    // would appear to be over the moment it was written. Refusing here names the
    // cause; the silent version does not.
    if (
      !loopback &&
      hostname !== undefined &&
      hostname !== options.domain &&
      !hostname.endsWith(`.${options.domain}`)
    ) {
      throw new Error(
        `A cookie cannot be scoped to '${options.domain}' from '${hostname}': the domain has to be this host or one above it`,
      );
    }

    const secure = globalThis.location?.protocol === 'https:';
    this.#attributes = [
      // Host-only on loopback: browsers reject `Domain=localhost`, and a
      // host-only cookie already spans ports, which local multi-origin needs.
      ...(loopback ? [] : [`Domain=${options.domain}`]),
      'Path=/',
      'SameSite=Lax',
      // Loopback is a secure context, but a `Secure` cookie over http is not
      // reliably accepted.
      ...(secure ? ['Secure'] : []),
    ].join('; ');

    // The check above cannot see a public suffix: 'app.co.uk' ends with '.co.uk',
    // so `domain: 'co.uk'` passes it and the browser then refuses the cookie. No
    // API exposes the list, so the only test that agrees with the browser is to
    // write one and read it back — which catches cookies being switched off at
    // the same time.
    if (!this.isReadOnly) {
      const probe = 'ic-cookie-probe';
      let accepted = false;
      try {
        // No Max-Age, so even a cleanup that fails dies with the browser.
        // biome-ignore lint/suspicious/noDocumentCookie: as elsewhere in this class.
        document.cookie = `${probe}=1; ${this.#attributes}`;
        accepted = readCookie(probe) !== null;
      } finally {
        // biome-ignore lint/suspicious/noDocumentCookie: as above.
        document.cookie = `${probe}=; ${this.#attributes}; Max-Age=0`;
      }
      if (!accepted) {
        throw new Error(
          `A cookie scoped to '${options.domain}' cannot be written from '${hostname}': the browser refused it. The domain may be a public suffix, or cookies may be disabled.`,
        );
      }
    }
  }

  /**
   * Resolves once every key read so far has its answer loaded, in a worker.
   * Already resolved in a tab, which reads the cookie itself.
   */
  public async ready(): Promise<void> {
    while (this.#pendingLoads.size > 0) await Promise.all([...this.#pendingLoads]);
  }

  public get(key: string): SessionState | null {
    if (this.isReadOnly) {
      if (!this.#loadedKeys.has(key)) {
        this.#loadedKeys.add(key);
        this.#track(this.#load(key));
      }
      return this.#answers.get(key) ?? null;
    }
    const state = this.#answer(key);
    this.#publish(key, state);
    return state;
  }

  public set(key: string, state: Omit<SessionState, 'held'>): void {
    if (this.isReadOnly) throw readOnlyError();
    this.#write(key, () => {
      // The claim first, so nothing reads the cookie as held before it is.
      this.#claim.set(key, state);
      this.#writeCookie(key, `${state.principal.toText()}|${state.expiration.toString()}`);
    });
  }

  public remove(key: string): void {
    if (this.isReadOnly) throw readOnlyError();
    this.#write(key, () => {
      this.#writeCookie(key, null);
      this.#claim.remove(key);
    });
  }

  /**
   * Drops this origin's claim on the sign-in, leaving the cookie for the siblings.
   *
   * An origin whose chain turns out to be dead cannot tell a revoked session from
   * one a sibling replaced by signing in, and in the second case that sibling
   * wrote this cookie a moment ago. So the record stands and this origin reads it
   * as not held, which is what sends it to acquire one of its own.
   */
  public discard(key: string): void {
    if (this.isReadOnly) throw readOnlyError();
    this.#write(key, () => this.#claim.remove(key));
  }

  /**
   * Fires when the state changes, including when a sibling subdomain changes it.
   *
   * `document.cookie` raises no event and no `BroadcastChannel` crosses origins,
   * so a sibling's sign-out is visible only by looking: the Cookie Store API
   * where the browser has it, and otherwise a re-check whenever this page is
   * shown or its window regains focus, which is when the user is about to act on
   * the answer. A worker hears of a change when a tab publishes it.
   */
  public subscribe(key: string, listener: () => void): () => void {
    // One logical change can arrive from several sources at once, so each is
    // routed through a check that fires only when the answer actually changed
    // since the last one.
    //
    // Compared on what `get` answers and not on the cookie alone. `held` is the
    // per-origin half, and `discard` changes only that — leaving the cookie for
    // the siblings is the whole point of it — so watching the cookie would make
    // this origin losing its claim the one change nothing reported.
    let last = stateOf(this.get(key));
    const check = (): void => {
      if (this.#writeDepth > 0) return;
      const now = stateOf(this.get(key));
      if (now !== last) {
        last = now;
        listener();
      }
    };
    const listeners = this.#subscribers.get(key) ?? new Set();
    listeners.add(check);
    this.#subscribers.set(key, listeners);

    if (this.isReadOnly) {
      // Nothing was followed while this store had no subscribers, so what it
      // loaded before may have changed since. `ready()` waits for the reload.
      if (this.#subscriberCount++ === 0) {
        for (const loadedKey of this.#loadedKeys) this.#track(this.#load(loadedKey));
      }
      const stopListening = this.#doorbell.listen();
      let isSubscribed = true;
      return () => {
        if (!isSubscribed) return;
        isSubscribed = false;
        this.#subscriberCount--;
        listeners.delete(check);
        stopListening();
      };
    }

    // The claim is in `localStorage`, which raises `storage` in every tab of this
    // origin but the one that wrote. That is how a tab hears that another tab
    // dropped this origin's claim, which no cookie event can carry.
    const unwatchClaim = this.#claim.subscribe(key, check);
    const onVisible = (): void => {
      if (document.visibilityState === 'visible') check();
    };
    document.addEventListener('visibilitychange', onVisible);
    globalThis.addEventListener('pageshow', check);
    globalThis.addEventListener('focus', check);

    const cookieStore = (globalThis as { cookieStore?: EventTarget }).cookieStore;
    cookieStore?.addEventListener('change', check);

    return () => {
      listeners.delete(check);
      unwatchClaim();
      document.removeEventListener('visibilitychange', onVisible);
      globalThis.removeEventListener('pageshow', check);
      globalThis.removeEventListener('focus', check);
      cookieStore?.removeEventListener('change', check);
    };
  }

  #fire(key: string): void {
    for (const check of [...(this.#subscribers.get(key) ?? [])]) check();
  }

  #write(key: string, write: () => void): void {
    this.#writeDepth++;
    try {
      write();
    } finally {
      this.#writeDepth--;
    }
    this.#fire(key);
    this.#publish(key, this.#answer(key));
  }

  /** A tab's answer: the cookie, and whether this origin's claim matches it. */
  #answer(key: string): SessionState | null {
    const raw = readCookie(key);
    if (raw === null) return null;

    const [principalText, expiration] = raw.split('|');
    if (principalText === undefined || expiration === undefined) return null;
    try {
      const principal = Principal.fromText(principalText);
      // Compared, not merely counted: a record can outlive the sign-in it was
      // written for — an expired one is kept on purpose, so an application can
      // say the session ended — and a sibling signing in as someone else then
      // publishes a cookie this origin has no credential for. Asking only whether
      // some local record exists would read that as held.
      // The record's own fields are the shared truth, read as written. `held` is
      // the only thing derived here, because it is the one fact a record every
      // sibling reads cannot carry.
      const claim = this.#claim.get(key);
      return {
        principal,
        expiration: BigInt(expiration),
        held: claim !== null && claim.principal.compareTo(principal) === 'eq',
      };
    } catch {
      return null;
    }
  }

  #writeCookie(key: string, raw: string | null): void {
    // biome-ignore lint/suspicious/noDocumentCookie: the Cookie Store API is async, and this record is read synchronously alongside isAuthenticated().
    document.cookie =
      raw === null
        ? `${encodeURIComponent(key)}=; ${this.#attributes}; Max-Age=0`
        : `${encodeURIComponent(key)}=${encodeURIComponent(raw)}; ${this.#attributes}; Max-Age=${RECORD_MAX_AGE_SECONDS}`;
  }

  /**
   * Publishes a tab's answer for the workers of its origin, when it changed.
   *
   * The answer is worked out again under the lock, at the moment it is written,
   * so the last tab to write publishes what is true then rather than what it saw
   * earlier.
   */
  #publish(key: string, state: SessionState | null): void {
    const answer = stateOf(state);
    if (this.#published.get(key) === answer) return;
    this.#published.set(key, answer);
    void withLock(`${ANSWER_CHANNEL}:${key}`, async () => {
      const current = stateOf(this.#answer(key));
      await (await this.#db).set<StoredAnswer>(answerKey(key), {
        raw: current === '' ? null : current,
      });
      // What was written, which may be newer than what queued this.
      this.#published.set(key, current);
      this.#doorbell.ring({ key });
    }).catch(() => {
      // No IndexedDB here, or the write failed. Forgotten, so the next read
      // tries again; tabs read the cookie themselves meanwhile.
      this.#published.delete(key);
    });
  }

  #receive(data: unknown): void {
    if (!this.isReadOnly || !isAnnouncement(data)) return;
    this.#track(this.#load(data.key));
  }

  #track(work: Promise<void>): void {
    const tracked = work.catch(() => undefined).finally(() => this.#pendingLoads.delete(tracked));
    this.#pendingLoads.add(tracked);
  }

  async #load(key: string): Promise<void> {
    const version = (this.#versions.get(key) ?? 0) + 1;
    this.#versions.set(key, version);
    const stored = await (await this.#db).get<StoredAnswer>(answerKey(key));
    // A load started later is newer than this one.
    if (this.#versions.get(key) !== version) return;
    this.#answers.set(key, parseAnswer(stored?.raw ?? null));
    this.#fire(key);
  }

  // Opened on first use, and forgotten again if opening failed, so a later call
  // retries rather than reusing a rejected promise.
  #dbPromise: Promise<IdbKeyVal> | null = null;
  get #db(): Promise<IdbKeyVal> {
    if (this.#dbPromise === null) {
      const promise = IdbKeyVal.create(STATE_DB).catch((error) => {
        if (this.#dbPromise === promise) {
          this.#dbPromise = null;
        }
        throw error;
      });
      this.#dbPromise = promise;
    }
    return this.#dbPromise;
  }
}

/**
 * What {@link CookieStateStorage.get} answers, as one comparable string, which
 * is also how a tab publishes it for its workers.
 *
 * Both halves in it: the cookie every sibling reads, and the `held` this origin
 * derives, because a change in either is a change to the answer.
 */
const stateOf = (state: SessionState | null): string =>
  state === null ? '' : `${state.principal.toText()}|${state.expiration}|${state.held}`;

/** Reads what {@link stateOf} wrote, or `null` for anything else. */
function parseAnswer(raw: string | null): SessionState | null {
  if (raw === null) return null;
  const [principalText, expiration, held] = raw.split('|');
  if (principalText === undefined || expiration === undefined || held === undefined) return null;
  try {
    return {
      principal: Principal.fromText(principalText),
      expiration: BigInt(expiration),
      held: held === 'true',
    };
  } catch {
    return null;
  }
}

/** Reads a cookie value by name, or `null` if absent. */
function readCookie(name: string): string | null {
  for (const entry of document.cookie.split(';')) {
    const separator = entry.indexOf('=');
    if (separator === -1) continue;
    // Any cookie on this domain lands here, including ones this library did not
    // write. A stray `%` makes `decodeURIComponent` throw, and one unrelated
    // cookie must not be able to break reading the state.
    try {
      if (decodeURIComponent(entry.slice(0, separator).trim()) !== name) continue;
      return decodeURIComponent(entry.slice(separator + 1).trim());
    } catch {}
  }
  return null;
}
