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
const STATE_DB: DBCreateOptions = { dbName: 'auth-client-state-db', storeName: 'ic-state' };

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
 * A write updates the copy straight away and is written to IndexedDB without the
 * writer waiting for it. Writes to IndexedDB take a Web Lock per key, so they
 * land in the order they were made, across contexts. Once a write has committed,
 * it is announced on a `BroadcastChannel`, and every other store reads IndexedDB
 * again and updates its copy. Announcing only after the commit means a reader
 * always finds the write it was told about.
 *
 * {@link ready} resolves once the copy has been brought up to date with
 * IndexedDB. The client waits for it before restoring a session, so a worker
 * needs nothing more than:
 *
 * ```ts
 * const client = new AuthClient({ stateStorage: new IdbStateStorage() });
 * ```
 * @see implements {@link StateStorage}
 */
export class IdbStateStorage implements StateStorage {
  readonly #copy: LocalStateStorage | MemoryStateStorage;
  readonly #channel: BroadcastChannel | undefined;
  readonly #ready: Promise<void>;

  // Bumped by every write and every read of IndexedDB, per key. A read that
  // finishes after the number moved on is older than what the copy holds.
  readonly #versions = new Map<string, number>();

  // Writes made here that have not yet committed, per key. The copy already
  // holds them, so a read of IndexedDB in the meantime is older.
  readonly #pendingWrites = new Map<string, number>();

  // Reads of IndexedDB in progress, which `ready()` waits for.
  readonly #rereads = new Set<Promise<void>>();

  // Keys whose record in `localStorage` has been reconciled with IndexedDB.
  readonly #reconciledKeys = new Set<string>();

  constructor() {
    this.#copy = hasLocalStorage() ? new LocalStateStorage() : new MemoryStateStorage();
    this.#channel =
      typeof BroadcastChannel === 'undefined' ? undefined : new BroadcastChannel(STATE_CHANNEL);
    // Listening before the first read, so a write that commits during it is not missed.
    this.#channel?.addEventListener('message', (event) => this.#receive(event.data));
    this.#ready = this.#loadAll();
  }

  /**
   * Resolves once this store's copy agrees with IndexedDB. Never rejects: where
   * IndexedDB is unavailable, the copy is all there is.
   */
  public ready(): Promise<void> {
    return this.#ready;
  }

  /**
   * Stops listening for changes from other contexts.
   *
   * Only needed when replacing a store while the page or worker lives on.
   */
  public close(): void {
    this.#channel?.close();
  }

  public get(key: string): SessionState | null {
    if (this.#copy instanceof LocalStateStorage && !this.#reconciledKeys.has(key)) {
      this.#reconciledKeys.add(key);
      this.#track(this.#reconcile(key));
    }
    return this.#copy.get(key);
  }

  public set(key: string, state: Omit<SessionState, 'held'>): void {
    // Queued before the copy changes, because changing it notifies subscribers,
    // and a write one of them makes has to land after this one.
    this.#persist(key, formatState(state));
    this.#copy.set(key, state);
  }

  public remove(key: string): void {
    this.#persist(key, null);
    this.#copy.remove(key);
  }

  /** The same as {@link remove}: this store publishes nothing beyond the origin. */
  public discard(key: string): void {
    this.remove(key);
  }

  public subscribe(key: string, listener: () => void): () => void {
    return this.#copy.subscribe(key, listener);
  }

  #bump(key: string): number {
    const version = (this.#versions.get(key) ?? 0) + 1;
    this.#versions.set(key, version);
    return version;
  }

  #persist(key: string, raw: string | null): void {
    this.#bump(key);
    this.#pendingWrites.set(key, (this.#pendingWrites.get(key) ?? 0) + 1);
    void this.#withLock(key, async () => {
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
    try {
      this.#channel?.postMessage({ key } satisfies Announcement);
    } catch {
      // A closed channel: nobody here is listening any more.
    }
  }

  #receive(data: unknown): void {
    if (!isAnnouncement(data)) return;
    this.#track(this.#reread(data.key));
  }

  #track(work: Promise<void>): void {
    const tracked = work.catch(() => undefined).finally(() => this.#rereads.delete(tracked));
    this.#rereads.add(tracked);
  }

  async #reread(key: string): Promise<void> {
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

  async #loadAll(): Promise<void> {
    try {
      const versions = new Map(this.#versions);
      const entries = await (await this.#db).entries<StoredState>();
      for (const [key, stored] of entries) {
        if (typeof key !== 'string') continue;
        // Anything written or read under this key since is newer than this snapshot.
        if (this.#versions.get(key) !== versions.get(key)) continue;
        this.#apply(key, stored.raw);
      }
    } catch {
      // No IndexedDB here: the copy is all there is.
    }
    // A read started by an announcement is newer than the snapshot, so it has to
    // land before the copy can be called up to date.
    while (this.#rereads.size > 0) await Promise.all([...this.#rereads]);
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

  #withLock<T>(key: string, work: () => Promise<T>): Promise<T> {
    const locks = globalThis.navigator?.locks;
    // Without Web Locks, writes from different contexts can land out of order.
    if (locks === undefined) return work();
    return locks.request(`${STATE_CHANNEL}:${key}`, work) as Promise<T>;
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
