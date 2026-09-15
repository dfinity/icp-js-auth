import { Principal } from '@icp-sdk/core/principal';
import { LocalStateStorage, type SessionState, type StateStorage } from './state-storage.js';

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

  readonly #attributes: string;
  #subscribers = new Map<string, Set<() => void>>();

  // The cookie is the domain's and says who is signed in; this says whether it
  // was this origin that acquired a credential for them. A cookie cannot carry
  // that — every sibling reads the same bytes — so it is kept per origin and
  // composed in on read, under the same key the cookie uses.
  readonly #local = new LocalStateStorage();

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
    if (typeof document !== 'undefined') {
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

  public get(key: string): SessionState | null {
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
      const local = this.#local.get(key);
      return {
        principal,
        expiration: BigInt(expiration),
        held: local !== null && local.principal.compareTo(principal) === 'eq',
      };
    } catch {
      return null;
    }
  }

  public set(key: string, state: Omit<SessionState, 'held'>): void {
    const seconds = Number((state.expiration - BigInt(Date.now()) * 1_000_000n) / 1_000_000_000n);
    if (seconds <= 0) {
      // Already over, so there is no state to publish: writing it would announce
      // a sign-in that has ended.
      this.remove(key);
      return;
    }
    // The local record first, so nothing reads the cookie as held before it is.
    this.#local.set(key, state);
    const payload = `${state.principal.toText()}|${state.expiration.toString()}`;
    // biome-ignore lint/suspicious/noDocumentCookie: the Cookie Store API is async, and this record is read synchronously alongside isAuthenticated().
    document.cookie = `${encodeURIComponent(key)}=${encodeURIComponent(payload)}; ${this.#attributes}; Max-Age=${seconds}`;
    this.#fire(key);
  }

  public remove(key: string): void {
    this.#local.remove(key);
    // biome-ignore lint/suspicious/noDocumentCookie: same reason as set().
    document.cookie = `${encodeURIComponent(key)}=; ${this.#attributes}; Max-Age=0`;
    this.#fire(key);
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
    this.#local.remove(key);
    this.#fire(key);
  }

  /**
   * Fires when the state changes, including when a sibling subdomain changes it.
   *
   * `document.cookie` raises no event and no `BroadcastChannel` crosses origins,
   * so a sibling's sign-out is visible only by looking: the Cookie Store API
   * where the browser has it, and otherwise a re-check whenever this page is
   * shown or its window regains focus, which is when the user is about to act on
   * the answer.
   */
  public subscribe(key: string, listener: () => void): () => void {
    // One logical change can arrive from several sources at once, so each is
    // routed through a check that fires only when what is stored actually
    // changed since the last one.
    //
    // Compared on what `get` answers and not on the cookie alone. `held` is the
    // per-origin half, and `discard` changes only that — leaving the cookie for
    // the siblings is the whole point of it — so watching the cookie would make
    // this origin losing its claim the one change nothing reported.
    let last = stateOf(this.get(key));
    const check = (): void => {
      const now = stateOf(this.get(key));
      if (now !== last) {
        last = now;
        listener();
      }
    };
    const listeners = this.#subscribers.get(key) ?? new Set();
    listeners.add(check);
    this.#subscribers.set(key, listeners);

    const onVisible = (): void => {
      if (document.visibilityState === 'visible') check();
    };
    // The local half is in `localStorage`, which raises `storage` in every tab
    // of this origin but the one that wrote. That is how a sibling tab hears
    // that this origin dropped its claim, which no cookie event can carry.
    const onStorage = (event: StorageEvent): void => {
      // `key` is null when a tab cleared the whole store, which changes this too.
      if (event.key === key || event.key === null) check();
    };
    globalThis.addEventListener('storage', onStorage);
    document.addEventListener('visibilitychange', onVisible);
    globalThis.addEventListener('pageshow', check);
    globalThis.addEventListener('focus', check);

    const cookieStore = (globalThis as { cookieStore?: EventTarget }).cookieStore;
    cookieStore?.addEventListener('change', check);

    return () => {
      listeners.delete(check);
      globalThis.removeEventListener('storage', onStorage);
      document.removeEventListener('visibilitychange', onVisible);
      globalThis.removeEventListener('pageshow', check);
      globalThis.removeEventListener('focus', check);
      cookieStore?.removeEventListener('change', check);
    };
  }

  #fire(key: string): void {
    for (const check of [...(this.#subscribers.get(key) ?? [])]) check();
  }
}

/**
 * What {@link CookieStateStorage.get} answers, as one comparable string.
 *
 * Both halves in it: the cookie every sibling reads, and the `held` this origin
 * derives, because a change in either is a change to the answer.
 */
const stateOf = (state: SessionState | null): string =>
  state === null ? '' : `${state.principal.toText()}|${state.expiration}|${state.held}`;

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
