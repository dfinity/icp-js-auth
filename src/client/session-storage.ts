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
 * I/O ({@link LocalSessionStorage}) or shared across sibling subdomains
 * ({@link CookieSessionStorage}). {@link subscribe} lets {@link AuthClient} react
 * to a sign-in or sign-out that happened in another tab or on a sibling origin.
 * The implementation owns its storage slot.
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
   * What signing out does. For {@link CookieSessionStorage} that includes the
   * cross-subdomain hint, so every sibling of the domain stops offering a session
   * that is being ended deliberately.
   */
  remove(): void;

  /**
   * Removes the stored session for this origin, leaving anything shared alone.
   *
   * What finding out does, which is a different act. A session serves every
   * sibling of a domain, so an origin discovering that the chain it held is stale
   * has learned something about itself, not about the domain: a sibling may have
   * signed in a moment ago and written a hint that is perfectly good. Removing it
   * would tell that sibling its own session had gone.
   */
  discard(): void;

  /**
   * Registers a listener fired when the stored session changes outside this
   * client (another tab, or a sibling origin for {@link CookieSessionStorage}).
   * Returns a function that unregisters the listener.
   */
  subscribe(listener: () => void): () => void;
}
