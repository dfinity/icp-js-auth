import { type DBCreateOptions, IdbKeyVal } from './db.js';
import {
  formatState,
  LocalStateStorage,
  MemoryStateStorage,
  parseState,
  type SessionState,
  type StateStorage,
} from './state-storage.js';

/** The database the state is copied into, apart from the credentials' database. */
const STATE_DB: DBCreateOptions = { dbName: 'auth-client-state-db', storeName: 'ic-state' };

/** The channel a store announces on once a write has reached IndexedDB. */
const STATE_CHANNEL = 'ic-session-state';

/**
 * One record in IndexedDB.
 *
 * `raw` is `null` for a sign-out, which is kept rather than deleted, so that a
 * missing entry means "never written". That is what lets a tab copy a record
 * from `localStorage` into IndexedDB without undoing a sign-out.
 */
interface StoredState {
  raw: string | null;
}

/**
 * Announces that the record under `key` changed in IndexedDB. Carries no state:
 * a receiver reads IndexedDB again.
 *
 * `from` says which kind of store wrote it. One backed by `localStorage` ignores
 * another one's announcement, because the `storage` event has already told it.
 */
interface Changed {
  key: string;
  from: 'local' | 'memory';
}

const isChanged = (value: unknown): value is Changed => {
  if (typeof value !== 'object' || value === null) return false;
  const message = value as { key?: unknown; from?: unknown };
  return typeof message.key === 'string' && (message.from === 'local' || message.from === 'memory');
};

const localStorageAvailable = (): boolean => {
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
 * Where `localStorage` exists, which is a tab, the state is kept there exactly as
 * {@link LocalStateStorage} keeps it: same key, same format, so a sign-in made by
 * an earlier version reads as it is. Where it does not, which is a dedicated,
 * shared or service worker, the state is kept in memory and loaded from
 * IndexedDB.
 *
 * Every write is also copied to IndexedDB, without the writer waiting for it.
 * Once the copy has committed, the writer announces it on a `BroadcastChannel`,
 * and the other contexts read IndexedDB again. Announcing only after the commit
 * means a reader always finds the write it was told about.
 *
 * In a worker, wait for {@link ready} before constructing the client, so it starts
 * from the stored state:
 *
 * ```ts
 * const stateStorage = new IdbStateStorage();
 * await stateStorage.ready();
 * const client = new AuthClient({ stateStorage });
 * ```
 *
 * A client constructed earlier still catches up: it starts signed out and is told
 * when the stored state arrives.
 * @see implements {@link StateStorage}
 */
export class IdbStateStorage implements StateStorage {
  readonly #inner: LocalStateStorage | MemoryStateStorage;
  readonly #from: Changed['from'];
  readonly #channel: BroadcastChannel | undefined;
  readonly #ready: Promise<void>;

  // Bumped by every write and every read of IndexedDB, per key. A read that
  // finishes after the number moved on is older than what is already here.
  readonly #versions = new Map<string, number>();

  readonly #copied = new Set<string>();

  constructor() {
    const local = localStorageAvailable();
    this.#inner = local ? new LocalStateStorage() : new MemoryStateStorage();
    this.#from = local ? 'local' : 'memory';
    this.#channel =
      typeof BroadcastChannel === 'undefined' ? undefined : new BroadcastChannel(STATE_CHANNEL);
    // Listening before the first read, so a write that commits during it is not missed.
    this.#channel?.addEventListener('message', (event) => this.#receive(event.data));
    this.#ready = local ? Promise.resolve() : this.#readAll();
  }

  /**
   * Resolves once the state has been loaded from IndexedDB. Already resolved
   * where `localStorage` exists, and never rejects.
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
    if (this.#inner instanceof LocalStateStorage && !this.#copied.has(key)) {
      this.#copied.add(key);
      void this.#copyToIdb(key).catch(() => undefined);
    }
    return this.#inner.get(key);
  }

  public set(key: string, state: Omit<SessionState, 'held'>): void {
    this.#bump(key);
    this.#inner.set(key, state);
    this.#store(key, formatState(state));
  }

  public remove(key: string): void {
    this.#bump(key);
    this.#inner.remove(key);
    this.#store(key, null);
  }

  /** The same as {@link remove}: this store publishes nothing beyond the origin. */
  public discard(key: string): void {
    this.remove(key);
  }

  public subscribe(key: string, listener: () => void): () => void {
    return this.#inner.subscribe(key, listener);
  }

  #bump(key: string): number {
    const version = (this.#versions.get(key) ?? 0) + 1;
    this.#versions.set(key, version);
    return version;
  }

  #store(key: string, raw: string | null): void {
    void this.#db
      .then((db) => db.set<StoredState>(key, { raw }))
      .then(() => this.#announce(key))
      .catch(() => {
        // No IndexedDB here, or the write failed. This context's own state is
        // already written; other contexts keep what they have until the next
        // write reaches them.
      });
  }

  #announce(key: string): void {
    try {
      this.#channel?.postMessage({ key, from: this.#from } satisfies Changed);
    } catch {
      // A closed channel: nobody in this context is listening any more.
    }
  }

  #receive(data: unknown): void {
    if (!isChanged(data)) return;
    if (this.#from === 'local' && data.from === 'local') return;
    void this.#reread(data.key).catch(() => undefined);
  }

  async #reread(key: string): Promise<void> {
    const version = this.#bump(key);
    const before = this.#raw(key);
    const stored = await (await this.#db).get<StoredState>(key);
    if (this.#versions.get(key) !== version) return;
    // Another tab can write `localStorage` without this store seeing it, and
    // that write is newer than the one this read was started for.
    if (this.#raw(key) !== before) return;
    this.#apply(key, stored?.raw ?? null);
  }

  #raw(key: string): string | null {
    const state = this.#inner.get(key);
    return state === null ? null : formatState(state);
  }

  async #readAll(): Promise<void> {
    try {
      const entries = await (await this.#db).entries<StoredState>();
      for (const [key, stored] of entries) {
        // Anything written or read under this key since is newer than this snapshot.
        if (typeof key !== 'string' || this.#versions.has(key)) continue;
        this.#apply(key, stored.raw);
      }
    } catch {
      // No IndexedDB here: the store starts empty, as `MemoryStateStorage` does.
    }
  }

  #apply(key: string, raw: string | null): void {
    const state = parseState(raw);
    if (state === null) {
      this.#inner.remove(key);
    } else {
      this.#inner.set(key, state);
    }
  }

  // A sign-in kept in `localStorage` by an earlier version is copied once, so
  // workers find it without waiting for the next sign-in. Never over an entry
  // IndexedDB already has, a sign-out included: that entry is the newer one.
  async #copyToIdb(key: string): Promise<void> {
    const version = this.#versions.get(key) ?? 0;
    const state = this.#inner.get(key);
    if (state === null) return;
    const db = await this.#db;
    if ((await db.get<StoredState>(key)) !== null) return;
    if ((this.#versions.get(key) ?? 0) !== version) return;
    await db.set<StoredState>(key, { raw: formatState(state) });
    this.#announce(key);
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
