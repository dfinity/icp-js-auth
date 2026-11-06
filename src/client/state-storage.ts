import { Principal } from '@icp-sdk/core/principal';
import { IdbKeyVal } from './db.js';

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

  /** Resolves once a worker has loaded the keys subscribed to so far. */
  public ready(): Promise<void> {
    return this.#loads;
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
