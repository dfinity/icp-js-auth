import { Principal } from '@icp-sdk/core/principal';
import { IdbKeyVal } from '../db.js';
import type { SessionState, StateStorage } from './state-storage.js';

/** Where tabs mirror their `localStorage` records for workers, which cannot read it. */
const MIRROR_DB = { dbName: 'auth-client-state-db', storeName: 'ic-keyval' };

/** The channel a tab announces a mirrored record on, carrying only its key. */
const MIRROR_CHANNEL = 'ic-session-state';

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
 * State in `localStorage`, so every tab of an origin agrees on it and it
 * survives a reload.
 *
 * Workers cannot read `localStorage`, so a tab mirrors each record it writes or
 * subscribes to into IndexedDB and announces it, and a worker loads the mirror
 * into memory. A worker changes nothing: signing in and out happens in a page.
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

  /** True in a worker, which reads what its tabs mirror and changes nothing. */
  public readonly isReadOnly = !hasLocalStorage();

  // In a worker: the mirrored records, and the loads that fill them, one after
  // another so a later load always lands last.
  readonly #mirrored = new Map<string, string | null>();
  #loads: Promise<void> = Promise.resolve();

  /** Resolves once a worker has loaded the keys subscribed to so far, and every load queued meanwhile. */
  public async ready(): Promise<void> {
    let loads: Promise<void>;
    do {
      loads = this.#loads;
      await loads;
    } while (loads !== this.#loads);
  }

  public get(key: string): SessionState | null {
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
    void this.#mirror(key);
  }

  public remove(key: string): void {
    if (this.isReadOnly) throw readOnlyError();
    this.#localStorage().removeItem(key);
    this.#fire(key);
    void this.#mirror(key);
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

    // A tab mirrors what it holds now, which also repairs a mirror an earlier
    // version or a closing page left behind; a worker loads it. Afterwards each
    // announcement is a write in some tab: a worker loads it, and a tab re-checks,
    // because a write by another store in this tab raises no `storage` event.
    if (this.isReadOnly) {
      this.#load(key);
    } else {
      void this.#mirror(key);
    }
    const channel =
      typeof BroadcastChannel === 'undefined' ? undefined : new BroadcastChannel(MIRROR_CHANNEL);
    channel?.addEventListener('message', (event: MessageEvent<unknown>) => {
      if (event.data !== key) return;
      if (this.isReadOnly) {
        this.#load(key);
      } else {
        check();
      }
    });

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

    return () => {
      listeners.delete(check);
      channel?.close();
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

  /** Writes what `localStorage` holds under `key` to the mirror, and announces it. */
  async #mirror(key: string): Promise<void> {
    try {
      const db = await IdbKeyVal.create(MIRROR_DB);
      // Read after the await and right before the write: IndexedDB applies writes
      // in the order they are made, so the last to land holds what is current.
      await db.set(key, { raw: this.#raw(key) });
      const channel = new BroadcastChannel(MIRROR_CHANNEL);
      channel.postMessage(key);
      channel.close();
    } catch {
      // No IndexedDB or no channel here: workers keep what they have until the
      // next write reaches them.
    }
  }

  #load(key: string): void {
    this.#loads = this.#loads.then(async () => {
      try {
        const db = await IdbKeyVal.create(MIRROR_DB);
        this.#mirrored.set(key, (await db.get<{ raw: string | null }>(key))?.raw ?? null);
      } catch {
        // No IndexedDB here: the worker reads as signed out.
      }
      this.#fire(key);
    });
  }

  #localStorage(): Storage {
    const ls = globalThis.localStorage;
    if (!ls) {
      throw new Error('Could not find local storage.');
    }
    return ls;
  }
}
