import { Principal } from '@icp-sdk/core/principal';

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
 * This is what decides whether this origin is signed in and as whom. It is read
 * synchronously, because a page renders on the answer and cannot await one, and
 * that is why {@link AuthClient.isAuthenticated} needs no asynchronous read.
 *
 * A record can be stale — a session revoked at the canister still reads as
 * signed in until something calls and is refused — so it is the state as this
 * browser knows it rather than an authority against the network.
 */
export interface StateStorage {
  /** The state, or `null` where nothing is signed in within this store's reach. */
  get(): SessionState | null;

  set(state: Omit<SessionState, 'held'>): void;

  /**
   * Removes the state, and anything this store publishes beyond this origin.
   *
   * What signing out does: the user ended the sign-in, so a sibling reading a
   * shared record must stop seeing one.
   */
  remove(): void;

  /**
   * Removes what this origin holds, leaving anything shared alone.
   *
   * What finding out does, which is a different act. An origin whose chain turns
   * out to be dead cannot tell whether the session was revoked or replaced by a
   * sibling signing in — and in the second case the shared record was written by
   * that sibling a moment ago, so retracting it would tell it that the session it
   * just obtained is gone. Implemented where the two differ.
   */
  discard?(): void;

  /**
   * Registers a listener fired when the state changes outside this client.
   * Returns a function that unregisters it.
   *
   * Implemented where the medium can report a change, which is how a sign-out
   * elsewhere reaches this client.
   */
  subscribe?(listener: () => void): () => void;
}

/**
 * State held for the lifetime of the instance and shared with nothing.
 *
 * For tests and for environments with no `localStorage`, where a client is
 * alone and a reload starts from nothing.
 * @see implements {@link StateStorage}
 */
export class MemoryStateStorage implements StateStorage {
  #state: Omit<SessionState, 'held'> | null = null;

  public get(): SessionState | null {
    // Nothing reaches past this instance, so a record here is always one it holds.
    return this.#state === null ? null : { ...this.#state, held: true };
  }

  public set(state: Omit<SessionState, 'held'>): void {
    this.#state = state;
  }

  public remove(): void {
    this.#state = null;
  }

  /** The same as {@link remove}: this store publishes nothing at all. */
  public discard(): void {
    this.remove();
  }
}

// Distinct from the slot the delegation itself is stored under: what is written
// here is two public fields about a sign-in, not the credential behind it.
const DEFAULT_KEY = 'ic-session-state';

/**
 * State in `localStorage`, so every tab of an origin agrees on it and it
 * survives a reload.
 *
 * The two fields are written as `<principal>|<expiration>` rather than JSON,
 * because an expiration is a `bigint` and JSON has no way to carry one.
 * @see implements {@link StateStorage}
 */
export class LocalStateStorage implements StateStorage {
  // Fired on a same-tab write: `storage` reaches the other tabs of an origin and
  // deliberately not the one that wrote.
  #subscribers = new Set<() => void>();

  /**
   * @param key - Storage key for the state. Change it only to avoid a collision
   *   with another client under the same origin.
   */
  constructor(public readonly key = DEFAULT_KEY) {}

  public get(): SessionState | null {
    const raw = this.#localStorage().getItem(this.key);
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

  public set(state: Omit<SessionState, 'held'>): void {
    this.#localStorage().setItem(
      this.key,
      `${state.principal.toText()}|${state.expiration.toString()}`,
    );
    this.#fire();
  }

  public remove(): void {
    this.#localStorage().removeItem(this.key);
    this.#fire();
  }

  /** The same as {@link remove}: this store publishes nothing beyond the origin. */
  public discard(): void {
    this.remove();
  }

  /**
   * Fires when the state changes, here or in another tab of this origin.
   *
   * `localStorage` raises `storage` in every tab except the one that wrote, so
   * that event carries a change between tabs and a same-tab write is announced
   * directly. Either way the record is readable before it is announced, so a
   * listener asking who is signed in sees what it was told about.
   */
  public subscribe(listener: () => void): () => void {
    let last = this.#raw();
    const check = (): void => {
      const now = this.#raw();
      if (now !== last) {
        last = now;
        listener();
      }
    };
    this.#subscribers.add(check);

    const onStorage = (event: StorageEvent): void => {
      // `key` is null when a tab cleared the whole store, which changes this too.
      if (event.key === this.key || event.key === null) check();
    };
    globalThis.addEventListener('storage', onStorage);

    return () => {
      this.#subscribers.delete(check);
      globalThis.removeEventListener('storage', onStorage);
    };
  }

  #fire(): void {
    for (const check of this.#subscribers) check();
  }

  #raw(): string | null {
    return this.#localStorage().getItem(this.key);
  }

  #localStorage(): Storage {
    const ls = globalThis.localStorage;
    if (!ls) {
      throw new Error('Could not find local storage.');
    }
    return ls;
  }
}
