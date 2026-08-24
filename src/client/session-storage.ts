import type { DerEncodedPublicKey } from '@icp-sdk/core/agent';
import type { DelegationChain } from '@icp-sdk/core/identity';

/**
 * What a signed-in application holds.
 *
 * A record rather than a bare chain because a session is not a delegation: it is
 * what an application is given at sign-in, what its access is derived from, and
 * what outlives any one delegation minted from it.
 */
export interface Session {
  /** The chain the identity provider signed to this application's key. */
  chain: DelegationChain;

  /**
   * The account's key: what the application's canisters see as the caller, and
   * what every delegation minted from this session is rooted at.
   *
   * Stored rather than derived because the chain is rooted at the session's own
   * key, not the account's, so this is the only record of who is signed in until
   * something mints.
   */
  accountKey: DerEncodedPublicKey;
}

/**
 * Persists the session — the non-secret proof that the identity provider
 * authorized this application.
 *
 * Unlike {@link IdentityStorage}, this is synchronous and observable: a session
 * carries no private material, so it can live in a store readable without async
 * I/O, and an implementation is free to put it somewhere more than one origin can
 * read. {@link subscribe} lets {@link AuthClient} react to a sign-in or sign-out
 * that happened outside it. The implementation owns its storage slot.
 */
export interface SessionStorage {
  /**
   * Returns the stored session, or `null` if none is stored or it cannot be
   * parsed. Does not check expiry — that is the caller's concern.
   */
  get(): Session | null;

  /** Stores the session, replacing any existing one. */
  set(session: Session): void;

  /**
   * Removes the stored session, and anything this store shares beyond it.
   *
   * What signing out does: an implementation that publishes the session's
   * existence anywhere retracts that too, so nothing keeps offering a session
   * that is being ended deliberately.
   */
  remove(): void;

  /**
   * Removes this store's copy of the session, leaving anything shared alone.
   *
   * What finding out does, which is a different act. A copy that turns out to be
   * unusable says something about this store, not about the session: where the
   * session is shared, another reader's copy may be perfectly good, and
   * retracting the shared state would tell it otherwise.
   */
  discard(): void;

  /**
   * Registers a listener fired when the stored session changes outside this
   * client — another tab, or wherever else the implementation shares it from.
   * Returns a function that unregisters the listener.
   */
  subscribe(listener: () => void): () => void;
}
