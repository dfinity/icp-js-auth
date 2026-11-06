import { type DBCreateOptions, IdbKeyVal } from './db.js';
import {
  formatState,
  LocalStateStorage,
  MemoryStateStorage,
  parseState,
  type SessionState,
  type StateStorage,
} from './state-storage.js';

/** The database the state is kept in, apart from the credentials' database. */
export const STATE_DB: DBCreateOptions = { dbName: 'auth-client-state-db', storeName: 'ic-state' };

/** The channel a store announces on, and the prefix of the locks its writes take. */
const STATE_CHANNEL = 'ic-session-state';

/**
 * One record in IndexedDB.
 *
 * `raw` is `null` for a sign-out, which is kept rather than deleted, so that a
 * missing entry means "never written".
 */
interface StoredState {
  raw: string | null;
}

/**
 * Announces that the record under `key` changed in IndexedDB. Carries no state:
 * every receiver reads IndexedDB again.
 */
interface Announcement {
  key: string;
}

const isAnnouncement = (value: unknown): value is Announcement =>
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

const hasLocalStorage = (): boolean => {
  try {
    return globalThis.localStorage !== undefined && globalThis.localStorage !== null;
  } catch {
    // Reading `localStorage` throws where the browser blocks storage for the page.
    return false;
  }
};

/**
 * State that the tabs and the workers of an origin share.
 *
 * IndexedDB holds the state every context agrees on. Each context also keeps a
 * copy it can read synchronously: a tab in `localStorage`, exactly as
 * {@link LocalStateStorage} keeps it (same key, same format, so a sign-in made by
 * an earlier version reads as it is), and a dedicated, shared or service worker
 * in memory.
 *
 * Only tabs change the state. A worker reads it, follows it, and throws if asked
 * to change it: signing in and out happens in a page. A tab's write updates its
 * copy straight away and is written to IndexedDB without the tab waiting for it.
 * Writes to IndexedDB take a Web Lock per key, so they land in the order they
 * were made, across tabs. Once a write has committed, it is announced on a
 * `BroadcastChannel`, and every other store reads IndexedDB again and updates
 * its copy. Announcing only after the commit means a reader always finds the
 * write it was told about.
 *
 * {@link ready} resolves once the copy has been brought up to date with
 * IndexedDB. The client waits for it before restoring a session. In a worker,
 * where the copy starts empty, wait for `AuthClient.ready()` before reading the
 * client's status.
 * @see implements {@link StateStorage}
 */
export class IdbStateStorage implements StateStorage {
  /**
   * True in a worker, which reads the state the tabs of its origin write and
   * changes nothing itself.
   */
  public readonly isReadOnly: boolean;

  readonly #copy: LocalStateStorage | MemoryStateStorage;
  readonly #doorbell = new Doorbell(STATE_CHANNEL, (data) => this.#receive(data));

  // Bumped by every write and every read of IndexedDB, per key. A read that
  // finishes after the number moved on is older than what the copy holds.
  readonly #versions = new Map<string, number>();

  // Writes made here that have not yet committed, per key. The copy already
  // holds them, so a read of IndexedDB in the meantime is older.
  readonly #pendingWrites = new Map<string, number>();

  // Loads from IndexedDB in progress, which `ready()` waits for.
  readonly #pendingReads = new Set<Promise<void>>();

  // Keys whose stored record has been loaded into the copy, which happens the
  // first time each is read: the client names its key, so this store cannot
  // know them in advance.
  readonly #loadedKeys = new Set<string>();

  #subscriberCount = 0;

  constructor() {
    this.isReadOnly = !hasLocalStorage();
    this.#copy = this.isReadOnly ? new MemoryStateStorage() : new LocalStateStorage();
  }

  /**
   * Resolves once every key read so far has been loaded from IndexedDB, along
   * with any change announced in the meantime. Never rejects: where IndexedDB is
   * unavailable, the copy is all there is.
   */
  public async ready(): Promise<void> {
    while (this.#pendingReads.size > 0) await Promise.all([...this.#pendingReads]);
  }

  public get(key: string): SessionState | null {
    if (!this.#loadedKeys.has(key)) {
      this.#loadedKeys.add(key);
      this.#track(this.#copy instanceof LocalStateStorage ? this.#reconcile(key) : this.#load(key));
    }
    return this.#copy.get(key);
  }

  public set(key: string, state: Omit<SessionState, 'held'>): void {
    if (this.isReadOnly) throw readOnlyError();
    // Queued before the copy changes, because changing it notifies subscribers,
    // and a write one of them makes has to land after this one.
    this.#persist(key, formatState(state));
    this.#copy.set(key, state);
  }

  public remove(key: string): void {
    if (this.isReadOnly) throw readOnlyError();
    this.#persist(key, null);
    this.#copy.remove(key);
  }

  /** The same as {@link remove}: this store publishes nothing beyond the origin. */
  public discard(key: string): void {
    this.remove(key);
  }

  /**
   * Fires when the state under `key` changes, here or in another tab or worker
   * of this origin.
   *
   * Changes from other contexts are followed only while this store has a
   * subscriber, which a client has from construction until `dispose()`.
   */
  public subscribe(key: string, listener: () => void): () => void {
    const unsubscribe = this.#copy.subscribe(key, listener);
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
      unsubscribe();
      stopListening();
    };
  }

  #bump(key: string): number {
    const version = (this.#versions.get(key) ?? 0) + 1;
    this.#versions.set(key, version);
    return version;
  }

  #persist(key: string, raw: string | null): void {
    this.#bump(key);
    this.#pendingWrites.set(key, (this.#pendingWrites.get(key) ?? 0) + 1);
    void withLock(`${STATE_CHANNEL}:${key}`, async () => {
      try {
        await (await this.#db).set<StoredState>(key, { raw });
        this.#announce(key);
      } finally {
        this.#pendingWrites.set(key, (this.#pendingWrites.get(key) ?? 1) - 1);
      }
    }).catch(() => {
      // No IndexedDB here, or the write failed. This context's copy is already
      // written; other contexts keep what they have until the next write.
    });
  }

  #announce(key: string): void {
    this.#doorbell.ring({ key } satisfies Announcement);
  }

  #receive(data: unknown): void {
    if (!isAnnouncement(data)) return;
    this.#track(this.#load(data.key));
  }

  #track(work: Promise<void>): void {
    const tracked = work.catch(() => undefined).finally(() => this.#pendingReads.delete(tracked));
    this.#pendingReads.add(tracked);
  }

  async #load(key: string): Promise<void> {
    const version = this.#bump(key);
    const stored = await (await this.#db).get<StoredState>(key);
    if (this.#versions.get(key) !== version) return;
    this.#apply(key, stored?.raw ?? null);
  }

  /**
   * Brings a tab's `localStorage` record in line with IndexedDB.
   *
   * IndexedDB has the record when anything has written it since this version, a
   * sign-out included, and then it is the newer of the two. When it has nothing,
   * the record in `localStorage` was written by an earlier version, and is
   * copied across so workers find it. The check and the copy are one
   * transaction, so no write can land between them.
   */
  async #reconcile(key: string): Promise<void> {
    const version = this.#bump(key);
    const state = this.#copy.get(key);
    const db = await this.#db;
    if (state !== null && (await db.setIfAbsent<StoredState>(key, { raw: formatState(state) }))) {
      this.#announce(key);
      return;
    }
    const stored = await db.get<StoredState>(key);
    if (stored === null || this.#versions.get(key) !== version) return;
    this.#apply(key, stored.raw);
  }

  #apply(key: string, raw: string | null): void {
    if ((this.#pendingWrites.get(key) ?? 0) > 0) return;
    const state = parseState(raw);
    if (state === null) {
      this.#copy.remove(key);
    } else {
      this.#copy.set(key, state);
    }
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
