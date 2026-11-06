import { Principal } from '@icp-sdk/core/principal';
import { type DBCreateOptions, IdbKeyVal } from './db.js';

/**
 * What a client knows about its sign-in without holding a credential: which
 * account is signed in here, and when that ends.
 *
 * Both fields are public. The principal is what an application's canisters see
 * as the caller, and the expiration is what the identity provider granted, so
 * neither is a secret and both can live somewhere a page reads synchronously.
 */
export interface SessionState {
  principal: Principal;

  /** Nanoseconds since the epoch, matching `Delegation.expiration`. */
  expiration: bigint;

  /**
   * Whether this origin holds a credential for that account, or only knows the
   * sign-in exists.
   *
   * Derived on read and never published: where the record reaches further than
   * one origin, the record itself cannot carry a per-origin fact. A sibling
   * subdomain that has not acquired its own credential reads the sign-in with
   * `held: false`, which is what tells it to acquire one.
   */
  held: boolean;
}

/**
 * Holds the state of a sign-in.
 *
 * This is what decides whether this origin is signed in and as whom. It is a
 * store of its own because it has to be readable without awaiting, which a
 * credential store does not.
 *
 * A record can be stale — a session revoked at the canister still reads as
 * signed in until something calls and is refused — so it is the state as this
 * browser knows it rather than an authority against the network.
 */
export interface StateStorage {
  /** The state, or `null` where nothing is signed in within this store's reach. */
  get(key: string): SessionState | null;

  set(key: string, state: Omit<SessionState, 'held'>): void;

  /**
   * Removes the state, and anything this store publishes beyond this origin.
   *
   * What signing out does: the user ended the sign-in, so a sibling reading a
   * shared record must stop seeing one.
   */
  remove(key: string): void;

  /**
   * Removes what this origin holds, leaving anything shared alone.
   *
   * What finding out does, which is a different act. An origin whose chain turns
   * out to be dead cannot tell whether the session was revoked or replaced by a
   * sibling signing in — and in the second case the shared record was written by
   * that sibling a moment ago, so retracting it would tell it that the session it
   * just obtained is gone.
   *
   * A store that publishes nothing beyond this origin answers it with
   * {@link remove}, which is one line and the right answer.
   */
  discard(key: string): void;

  /**
   * Whether a sign-in kept in this store may be resumed without a ceremony.
   *
   * True only where the record reaches past this origin, because that is the
   * case a silent re-issue exists for: a sibling reads the sign-in, holds no
   * credential of its own, and needs the identity provider to remember the
   * session it can extend. A store the origin keeps to itself has nothing to
   * gain and would only be asking the provider to persist a sign-in on a device
   * where nothing wanted one kept.
   *
   * Absent means false, which is the answer for a store that never considered
   * the question.
   */
  readonly resumable?: boolean;

  /**
   * Registers a listener fired when the state under `key` changes, including
   * when something other than this client changed it. Returns a function that
   * unregisters it.
   *
   * Required rather than optional: two clients can share one store, even a
   * store with no medium behind it, and a client that cannot be told the record
   * changed under it goes on answering for a sign-in that is no longer there.
   */
  subscribe(key: string, listener: () => void): () => void;

  /**
   * Whether this store only reads the state here, as a store does in a worker.
   * The client then changes nothing: it cannot sign in or out, and a session it
   * finds unusable is left for a page of this origin to end.
   *
   * Absent means false.
   */
  readonly isReadOnly?: boolean;

  /**
   * Resolves once {@link get} answers with the stored state, for a store that
   * loads it asynchronously. The client waits for it before restoring a session:
   * a store still loading reads as signed out, and restoring from that would end
   * the session.
   *
   * Absent means the store is ready from the start.
   */
  ready?(): Promise<void>;
}

/**
 * State held for the lifetime of the instance and shared with nothing.
 *
 * For tests, and for a client that should share its sign-in with nothing: a
 * reload starts from nothing.
 * @see implements {@link StateStorage}
 */
export class MemoryStateStorage implements StateStorage {
  #state = new Map<string, Omit<SessionState, 'held'>>();
  #subscribers = new Map<string, Set<() => void>>();

  public get(key: string): SessionState | null {
    // Nothing reaches past this instance, so a record here is always one it holds.
    const state = this.#state.get(key);
    return state === undefined ? null : { ...state, held: true };
  }

  public set(key: string, state: Omit<SessionState, 'held'>): void {
    this.#state.set(key, state);
    this.#fire(key);
  }

  public remove(key: string): void {
    this.#state.delete(key);
    this.#fire(key);
  }

  /** The same as {@link remove}: this store publishes nothing at all. */
  public discard(key: string): void {
    this.remove(key);
  }

  /**
   * Fires when the state changes, which here means when something writes to
   * this instance.
   *
   * Nothing outside the process can reach a `Map`, so a medium is not what makes
   * this worth having: two clients can be handed the same instance, and this is
   * how the one that did not write finds out. Each listener is told only when the
   * record actually changed since it was last told, so a client's own writes do
   * not come back to it as news.
   */
  public subscribe(key: string, listener: () => void): () => void {
    let last = this.#raw(key);
    const check = (): void => {
      const now = this.#raw(key);
      if (now !== last) {
        last = now;
        listener();
      }
    };
    const listeners = this.#subscribers.get(key) ?? new Set();
    listeners.add(check);
    this.#subscribers.set(key, listeners);

    return () => {
      listeners.delete(check);
    };
  }

  #fire(key: string): void {
    for (const check of [...(this.#subscribers.get(key) ?? [])]) check();
  }

  // The same shape `LocalStateStorage` keeps, so "changed" means the same thing
  // in both: a record is one string, and comparing strings needs no field walk.
  #raw(key: string): string | null {
    const state = this.#state.get(key);
    return state === undefined
      ? null
      : `${state.principal.toText()}|${state.expiration.toString()}`;
  }
}

/** The database the state is kept in, apart from the credentials' database. */
export const STATE_DB: DBCreateOptions = { dbName: 'auth-client-state-db', storeName: 'ic-keyval' };

/** The channel a store announces on, and the prefix of the locks its writes take. */
export const STATE_CHANNEL = 'ic-session-state';

/** One mirrored record in IndexedDB: what `localStorage` holds, or `null` for none. */
export interface StoredState {
  raw: string | null;
}

/**
 * Announces that the record under `key` changed in IndexedDB. Carries no state:
 * every receiver reads IndexedDB again.
 */
export interface Announcement {
  key: string;
}

export const isAnnouncement = (value: unknown): value is Announcement =>
  typeof value === 'object' &&
  value !== null &&
  typeof (value as { key?: unknown }).key === 'string';

/**
 * A `BroadcastChannel` that is open only while something listens on it.
 *
 * Listening is tied to a store's subscribers, and a client unsubscribes in
 * `dispose()`, so a disposed client leaves nothing open. Ringing needs no
 * listener: with none, the message goes out on a channel opened for it alone.
 */
export class Doorbell {
  readonly #name: string;
  readonly #onMessage: (data: unknown) => void;
  #channel: BroadcastChannel | undefined;
  #listenerCount = 0;

  constructor(name: string, onMessage: (data: unknown) => void) {
    this.#name = name;
    this.#onMessage = onMessage;
  }

  /** Starts listening, and returns the function that stops. */
  public listen(): () => void {
    if (this.#listenerCount++ === 0 && typeof BroadcastChannel !== 'undefined') {
      this.#channel = new BroadcastChannel(this.#name);
      this.#channel.addEventListener('message', (event) => this.#onMessage(event.data));
    }
    let isListening = true;
    return () => {
      if (!isListening) return;
      isListening = false;
      if (--this.#listenerCount > 0) return;
      this.#channel?.close();
      this.#channel = undefined;
    };
  }

  public ring(message: unknown): void {
    try {
      if (this.#channel !== undefined) {
        this.#channel.postMessage(message);
        return;
      }
      if (typeof BroadcastChannel === 'undefined') return;
      const channel = new BroadcastChannel(this.#name);
      channel.postMessage(message);
      channel.close();
    } catch {
      // A payload this browser will not clone. Other contexts keep what they
      // have until the next message reaches them.
    }
  }
}

/**
 * Runs `work` under a Web Lock, so writes from different tabs land in the order
 * they were made. Without Web Locks it runs straight away.
 */
export function withLock<T>(name: string, work: () => Promise<T>): Promise<T> {
  const locks = globalThis.navigator?.locks;
  if (locks === undefined) return work();
  return locks.request(name, work) as Promise<T>;
}

/** What a store throws when asked to change the sign-in where it can only read it. */
export const readOnlyError = (): Error =>
  new Error(
    'The sign-in state is read-only in a worker: sign in and sign out from a page of this origin.',
  );

export const hasLocalStorage = (): boolean => {
  try {
    return globalThis.localStorage !== undefined && globalThis.localStorage !== null;
  } catch {
    // Reading `localStorage` throws where the browser blocks storage for the page.
    return false;
  }
};

/**
 * State in `localStorage`, so every tab of an origin agrees on it and it
 * survives a reload.
 *
 * Workers cannot read `localStorage`, so tabs mirror it into IndexedDB and a
 * worker reads the mirror into memory. A worker changes nothing: signing in and
 * out happens in a page. Each tab write is mirrored without the tab waiting, under
 * a Web Lock per key, from what `localStorage` holds when the lock is granted, so
 * the last write to land always mirrors the current state. A tab mirrors a key
 * again on its first read, which makes good a write lost to a closing page or
 * made by an earlier version. Once a write has committed, it is announced on a
 * `BroadcastChannel`, and workers read the mirror again.
 *
 * The two fields are written as `<principal>|<expiration>` rather than JSON,
 * because an expiration is a `bigint` and JSON has no way to carry one.
 * @see implements {@link StateStorage}
 */
export class LocalStateStorage implements StateStorage {
  // Fired on a same-tab write: `storage` reaches the other tabs of an origin and
  // deliberately not the one that wrote. Per key, because one store answers for
  // whatever key it is handed.
  #subscribers = new Map<string, Set<() => void>>();

  /**
   * True in a worker, which reads the state the tabs of its origin mirror and
   * changes nothing itself.
   */
  public readonly isReadOnly = !hasLocalStorage();

  // In a worker: the mirrored records, and the number of the latest load of
  // each. A load that finishes after the number moved on is older.
  readonly #mirrored = new Map<string, string | null>();
  readonly #versions = new Map<string, number>();

  // Keys read so far, each mirrored (in a tab) or loaded (in a worker) on its
  // first read: the client names its key, so this store cannot know them sooner.
  readonly #seenKeys = new Set<string>();

  // Mirrors and loads in progress, which `ready()` waits for.
  readonly #pendingWork = new Set<Promise<void>>();
  readonly #doorbell = new Doorbell(STATE_CHANNEL, (data) => this.#receive(data));
  #subscriberCount = 0;

  /**
   * Resolves once every key read so far is loaded (in a worker) or mirrored (in
   * a tab). Never rejects: where IndexedDB is unavailable, the copy is all there
   * is.
   */
  public async ready(): Promise<void> {
    while (this.#pendingWork.size > 0) await Promise.all([...this.#pendingWork]);
  }

  public get(key: string): SessionState | null {
    if (!this.#seenKeys.has(key)) {
      this.#seenKeys.add(key);
      this.#track(this.isReadOnly ? this.#load(key) : this.#mirror(key));
    }
    const raw = this.#raw(key);
    if (raw === null) return null;

    const [principalText, expiration] = raw.split('|');
    if (principalText === undefined || expiration === undefined) return null;
    try {
      return {
        principal: Principal.fromText(principalText),
        expiration: BigInt(expiration),
        // This record is written by this origin and read by no other, so having
        // one and holding a credential for it are the same thing.
        held: true,
      };
    } catch {
      return null;
    }
  }

  public set(key: string, state: Omit<SessionState, 'held'>): void {
    if (this.isReadOnly) throw readOnlyError();
    this.#localStorage().setItem(key, `${state.principal.toText()}|${state.expiration.toString()}`);
    this.#fire(key);
    this.#track(this.#mirror(key));
  }

  public remove(key: string): void {
    if (this.isReadOnly) throw readOnlyError();
    this.#localStorage().removeItem(key);
    this.#fire(key);
    this.#track(this.#mirror(key));
  }

  /** The same as {@link remove}: this store publishes nothing beyond the origin. */
  public discard(key: string): void {
    this.remove(key);
  }

  /**
   * Fires when the state changes, here or in another tab of this origin.
   *
   * `localStorage` raises `storage` in every tab except the one that wrote, so
   * that event carries a change between tabs and a same-tab write is announced
   * directly. Either way the record is readable before it is announced, so a
   * listener asking who is signed in sees what it was told about.
   */
  public subscribe(key: string, listener: () => void): () => void {
    let last = this.#raw(key);
    const check = (): void => {
      const now = this.#raw(key);
      if (now !== last) {
        last = now;
        listener();
      }
    };
    const listeners = this.#subscribers.get(key) ?? new Set();
    listeners.add(check);
    this.#subscribers.set(key, listeners);

    // A worker followed nothing while it had no subscribers, so what it loaded
    // before may have changed since. `ready()` waits for the reload.
    if (this.#subscriberCount++ === 0 && this.isReadOnly) {
      for (const seenKey of this.#seenKeys) this.#track(this.#load(seenKey));
    }
    const stopListening = this.#doorbell.listen();

    const onStorage = (event: StorageEvent): void => {
      // `key` is null when a tab cleared the whole store, which changes this too.
      if (event.key === key || event.key === null) check();
    };
    globalThis.addEventListener('storage', onStorage);

    // `storage` is the only notice this store gets, and a page restored from the
    // back-forward cache was not listening while it was frozen. So the record is
    // re-read when the page is shown or its window regains focus, which is when
    // somebody is about to act on the answer.
    const onVisible = (): void => {
      if (document.visibilityState === 'visible') check();
    };
    const hooked = typeof document !== 'undefined';
    if (hooked) {
      document.addEventListener('visibilitychange', onVisible);
      globalThis.addEventListener('pageshow', check);
      globalThis.addEventListener('focus', check);
    }

    let isSubscribed = true;
    return () => {
      if (!isSubscribed) return;
      isSubscribed = false;
      this.#subscriberCount--;
      stopListening();
      listeners.delete(check);
      globalThis.removeEventListener('storage', onStorage);
      if (hooked) {
        document.removeEventListener('visibilitychange', onVisible);
        globalThis.removeEventListener('pageshow', check);
        globalThis.removeEventListener('focus', check);
      }
    };
  }

  #fire(key: string): void {
    for (const check of [...(this.#subscribers.get(key) ?? [])]) check();
  }

  #raw(key: string): string | null {
    if (this.isReadOnly) return this.#mirrored.get(key) ?? null;
    return this.#localStorage().getItem(key);
  }

  #track(work: Promise<void>): void {
    const tracked = work.catch(() => undefined).finally(() => this.#pendingWork.delete(tracked));
    this.#pendingWork.add(tracked);
  }

  /** Writes what `localStorage` holds now to the mirror, if the mirror differs. */
  async #mirror(key: string): Promise<void> {
    await withLock(`${STATE_CHANNEL}:${key}`, async () => {
      const raw = this.#raw(key);
      const db = await this.#db;
      if ((await db.get<StoredState>(key))?.raw === raw) return;
      await db.set<StoredState>(key, { raw });
      this.#doorbell.ring({ key });
    });
  }

  // A worker reads the mirror again; a tab re-checks `localStorage`, because a
  // write by another store in the same tab raises no `storage` event here.
  #receive(data: unknown): void {
    if (!isAnnouncement(data)) return;
    if (this.isReadOnly) {
      this.#track(this.#load(data.key));
      return;
    }
    this.#fire(data.key);
  }

  async #load(key: string): Promise<void> {
    const version = (this.#versions.get(key) ?? 0) + 1;
    this.#versions.set(key, version);
    const stored = await (await this.#db).get<StoredState>(key);
    if (this.#versions.get(key) !== version) return;
    this.#mirrored.set(key, stored?.raw ?? null);
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

  #localStorage(): Storage {
    const ls = globalThis.localStorage;
    if (!ls) {
      throw new Error('Could not find local storage.');
    }
    return ls;
  }
}
