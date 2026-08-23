import type { DelegationChain } from '@icp-sdk/core/identity';

/**
 * What a signed-in application holds.
 *
 * A record rather than a bare chain because a session is not a delegation: it is
 * what an application is given at sign-in, and what its access is derived from.
 */
export interface Session {
  /** The chain the identity provider signed to this application's key. */
  chain: DelegationChain;
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

  /** Removes the stored session. */
  remove(): void;

  /**
   * Registers a listener fired when the stored session changes outside this
   * client (another tab, or a sibling origin for {@link CookieSessionStorage}).
   * Returns a function that unregisters the listener.
   */
  subscribe(listener: () => void): () => void;
}
