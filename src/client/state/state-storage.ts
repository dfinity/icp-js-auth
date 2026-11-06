import type { Principal } from '@icp-sdk/core/principal';

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
