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
}

/**
 * State held for the lifetime of the instance and shared with nothing.
 *
 * For tests and for environments with no `localStorage`, where a client is
 * alone and a reload starts from nothing.
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

// Distinct from the slot the delegation itself is stored under: what is written
// here is two public fields about a sign-in, not the credential behind it.
export const STATE_KEY = 'ic-session-state';

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
  // deliberately not the one that wrote. Per key, because one store answers for
  // whatever key it is handed.
  #subscribers = new Map<string, Set<() => void>>();

  public get(key: string): SessionState | null {
    const raw = this.#localStorage().getItem(key);
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
    this.#localStorage().setItem(key, `${state.principal.toText()}|${state.expiration.toString()}`);
    this.#fire(key);
  }

  public remove(key: string): void {
    this.#localStorage().removeItem(key);
    this.#fire(key);
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

    const onStorage = (event: StorageEvent): void => {
      // `key` is null when a tab cleared the whole store, which changes this too.
      if (event.key === key || event.key === null) check();
    };
    globalThis.addEventListener('storage', onStorage);

    return () => {
      listeners.delete(check);
      globalThis.removeEventListener('storage', onStorage);
    };
  }

  #fire(key: string): void {
    for (const check of [...(this.#subscribers.get(key) ?? [])]) check();
  }

  #raw(key: string): string | null {
    return this.#localStorage().getItem(key);
  }

  #localStorage(): Storage {
    const ls = globalThis.localStorage;
    if (!ls) {
      throw new Error('Could not find local storage.');
    }
    return ls;
  }
}
