import type { SignIdentity } from '@icp-sdk/core/agent';

/**
 * Persists the session signing identity — the key pair a delegation is issued
 * to.
 *
 * The implementation owns the key algorithm and the storage slot: {@link create}
 * generates a fresh identity of its own type and stores that same type.
 * Switching algorithms (e.g. ECDSA → Ed25519) therefore means switching the
 * implementation, not passing a flag. The interface exists so a caller chooses
 * where and how the key is held without the shape of the key material reaching
 * it.
 */
export interface IdentityStorage {
  /**
   * Mints a fresh session identity of this store's type and returns it
   * **without persisting it**. Call {@link set} to persist it — deferring the
   * write until authentication succeeds keeps a cancelled or failed sign-in
   * from overwriting an existing valid session's key.
   */
  create(): Promise<SignIdentity>;

  /**
   * Persists an identity previously returned by {@link create}. Called once a
   * delegation has been obtained for it (or, in the redirect flow, on the
   * outbound load, since the key must survive the page navigation).
   */
  set(identity: SignIdentity): Promise<void>;

  /**
   * Returns the persisted identity, or `null` if there is none or it cannot be
   * read back (absent, corrupt, or from an incompatible version).
   */
  get(): Promise<SignIdentity | null>;

  /**
   * Removes the persisted identity.
   */
  remove(): Promise<void>;
}
