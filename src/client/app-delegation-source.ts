import type { DerEncodedPublicKey, SignIdentity } from '@icp-sdk/core/agent';
import type { DelegationChain } from '@icp-sdk/core/identity';

/**
 * Thrown when the canister has no session behind the caller: revoked, expired,
 * pruned, or never one at all.
 *
 * This is the one terminal outcome. Everything else a mint can fail with, a
 * transport error or an internal canister error, leaves the session alone and is
 * worth retrying, so only this type may end a session.
 */
export class SessionGoneError extends Error {
  constructor(message = 'The session behind this identity no longer exists') {
    super(message);
    this.name = 'SessionGoneError';
  }
}

/**
 * A key and the delegation minted for it.
 *
 * One thing with one lifetime. The delegation carries the authority and lasts
 * five minutes; a key outliving it would carry none, so a mint makes both and
 * replaces both. Rotation falls out of refreshing rather than needing a rule of
 * its own.
 */
export interface AppCredential {
  key: SignIdentity;
  chain: DelegationChain;
}

/**
 * Where {@link SessionIdentity} gets an app delegation from.
 *
 * The identity decides *when* to mint; this decides *how*. Splitting them is
 * what lets the timing be tested without a replica, and what keeps the identity
 * free of any agent or canister id.
 */
export interface AppDelegationSource {
  /**
   * Mint a delegation from the session to `appPublicKey`.
   *
   * Rejects with {@link SessionGoneError} when the session is gone, and with
   * anything else when the attempt may be worth repeating.
   */
  mint(appPublicKey: DerEncodedPublicKey): Promise<DelegationChain>;
}
