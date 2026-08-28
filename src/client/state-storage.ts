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
  /** The state, or `null` where this origin is not signed in. */
  get(): SessionState | null;

  set(state: SessionState): void;

  remove(): void;

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
  #state: SessionState | null = null;

  public get(): SessionState | null {
    return this.#state;
  }

  public set(state: SessionState): void {
    this.#state = state;
  }

  public remove(): void {
    this.#state = null;
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
      return { principal: Principal.fromText(principalText), expiration: BigInt(expiration) };
    } catch {
      return null;
    }
  }

  public set(state: SessionState): void {
    this.#localStorage().setItem(
      this.key,
      `${state.principal.toText()}|${state.expiration.toString()}`,
    );
  }

  public remove(): void {
    this.#localStorage().removeItem(this.key);
  }

  #localStorage(): Storage {
    const ls = globalThis.localStorage;
    if (!ls) {
      throw new Error('Could not find local storage.');
    }
    return ls;
  }
}
