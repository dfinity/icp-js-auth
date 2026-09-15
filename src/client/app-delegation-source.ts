import type { DerEncodedPublicKey } from '@icp-sdk/core/agent';
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

/** Whether two DER-encoded keys are the same bytes. */
export const sameKey = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, i) => byte === b[i]);

/** The leaf of a chain: the key it authorises. */
export const delegatesTo = (chain: DelegationChain): Uint8Array | undefined =>
  chain.delegations[chain.delegations.length - 1]?.delegation.pubkey;

/**
 * Whether a chain's leaf authorises `keyDer` — the key that would sign with it.
 *
 * A chain paired with a key it does not authorise signs nothing the replica will
 * accept, and fails with a signature error that points at neither half. Every
 * place that holds both halves checks this.
 */
export const chainAuthorisesKey = (chain: DelegationChain, keyDer: Uint8Array): boolean => {
  const leaf = delegatesTo(chain);
  return leaf !== undefined && sameKey(new Uint8Array(leaf), new Uint8Array(keyDer));
};
