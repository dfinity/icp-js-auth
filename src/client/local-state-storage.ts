import { type DBCreateOptions, IdbKeyVal } from './db.js';
import {
  formatState,
  LocalStorageCopy,
  MemoryStateStorage,
  parseState,
  type SessionState,
  type StateStorage,
} from './state-storage.js';

/** The database the state is kept in, apart from the credentials' database. */
export const STATE_DB: DBCreateOptions = { dbName: 'auth-client-state-db', storeName: 'ic-keyval' };

/** The channel a store announces on, and the prefix of the locks its writes take. */
const STATE_CHANNEL = 'ic-session-state';

/** One mirrored record in IndexedDB: what `localStorage` holds, or `null` for none. */
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
 * State in `localStorage`, which the tabs and the workers of an origin share.
 *
 * A tab keeps the state in `localStorage` (same key and format as earlier
 * versions, so a sign-in made by one reads as it is), and that is what every tab
 * agrees on. Workers cannot read
 * `localStorage`, so tabs mirror it into IndexedDB and a worker reads the
 * mirror. A worker keeps its own copy in memory and changes nothing: signing in
 * and out happens in a page.
 *
 * Every tab write is mirrored without the tab waiting for it, under a Web Lock
 * per key, and the mirror is written from what `localStorage` holds when the
 * lock is granted. So the last write to land always mirrors the current state,
 * whatever order the tabs' writes were queued in, and a write lost to a closing
 * page is made good by the next tab to read the key. Once a write has committed,
 * it is announced on a `BroadcastChannel`, and workers read the mirror again.
 *
 * {@link ready} resolves once a worker's copy has been loaded from the mirror.
 * The client waits for it before restoring a session. In a worker, wait for
 * `AuthClient.ready()` before reading the client's status.
 * @see implements {@link StateStorage}
 */
export class LocalStateStorage implements StateStorage {
  /**
   * True in a worker, which reads the state the tabs of its origin write and
   * changes nothing itself.
   */
  public readonly isReadOnly: boolean;

  readonly #copy: LocalStorageCopy | MemoryStateStorage;
  readonly #doorbell = new Doorbell(STATE_CHANNEL, (data) => this.#receive(data));

  // Each subscriber's check, per key. An announcement runs them in a tab: a
  // write by another store in the same tab raises no `storage` event here.
  readonly #checks = new Map<string, Set<() => void>>();

  // Keys read so far: mirrored on first read in a tab, loaded on first read in
  // a worker. The client names its key, so this store cannot know them sooner.
  readonly #seenKeys = new Set<string>();

  // In a worker: one number per key, bumped by each load. A load that finishes
  // after the number moved on is older than the one that moved it.
  readonly #versions = new Map<string, number>();

  // Mirrors and loads in progress, which `ready()` waits for.
  readonly #pendingWork = new Set<Promise<void>>();

  #subscriberCount = 0;

  constructor() {
    this.isReadOnly = !hasLocalStorage();
    this.#copy = this.isReadOnly ? new MemoryStateStorage() : new LocalStorageCopy();
  }

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
      // In a tab, what an earlier version or a closing page left unmirrored.
      this.#track(this.isReadOnly ? this.#load(key) : this.#mirror(key));
    }
    return this.#copy.get(key);
  }

  public set(key: string, state: Omit<SessionState, 'held'>): void {
    if (this.isReadOnly) throw readOnlyError();
    this.#copy.set(key, state);
    this.#track(this.#mirror(key));
  }

  public remove(key: string): void {
    if (this.isReadOnly) throw readOnlyError();
    this.#copy.remove(key);
    this.#track(this.#mirror(key));
  }

  /** The same as {@link remove}: this store publishes nothing beyond the origin. */
  public discard(key: string): void {
    this.remove(key);
  }

  /**
   * Fires when the state under `key` changes, here or in another tab of this
   * origin, or for a worker, in a tab.
   *
   * Changes from other contexts are followed only while this store has a
   * subscriber, which a client has from construction until `dispose()`.
   */
  public subscribe(key: string, listener: () => void): () => void {
    // One check for every source of news, so a change heard twice is told once.
    let last = this.#raw(key);
    const check = (): void => {
      const now = this.#raw(key);
      if (now === last) return;
      last = now;
      listener();
    };
    const checks = this.#checks.get(key) ?? new Set();
    checks.add(check);
    this.#checks.set(key, checks);
    const unsubscribe = this.#copy.subscribe(key, check);

    // A worker followed nothing while it had no subscribers, so what it loaded
    // before may have changed since. `ready()` waits for the reload.
    if (this.#subscriberCount++ === 0 && this.isReadOnly) {
      for (const seenKey of this.#seenKeys) this.#track(this.#load(seenKey));
    }
    const stopListening = this.#doorbell.listen();
    let isSubscribed = true;
    return () => {
      if (!isSubscribed) return;
      isSubscribed = false;
      this.#subscriberCount--;
      checks.delete(check);
      unsubscribe();
      stopListening();
    };
  }

  #raw(key: string): string | null {
    const state = this.#copy.get(key);
    return state === null ? null : formatState(state);
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
      this.#doorbell.ring({ key } satisfies Announcement);
    });
  }

  #receive(data: unknown): void {
    if (!isAnnouncement(data)) return;
    if (this.isReadOnly) {
      this.#track(this.#load(data.key));
      return;
    }
    for (const check of [...(this.#checks.get(data.key) ?? [])]) check();
  }

  async #load(key: string): Promise<void> {
    const version = (this.#versions.get(key) ?? 0) + 1;
    this.#versions.set(key, version);
    const stored = await (await this.#db).get<StoredState>(key);
    if (this.#versions.get(key) !== version) return;
    const state = parseState(stored?.raw ?? null);
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
