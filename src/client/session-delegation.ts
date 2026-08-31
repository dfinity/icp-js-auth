import type { DerEncodedPublicKey } from '@icp-sdk/core/agent';
import { Delegation, DelegationChain } from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import type { Signer } from '@icp-sdk/signer';
import { fromBase64, toBase64 } from './base64.js';

/**
 * The method Internet Identity answers with a session rather than a long-lived
 * delegation. Named for its provider because a JSON-RPC method travels over a
 * transport shared with other signers, unlike a canister method.
 */
const SESSION_DELEGATION_METHOD = 'ii_session_delegation';

/**
 * The code Internet Identity denies a `prompt: 'none'` request with.
 *
 * In ICRC-25's 3xxx user-action range, which is what lets a caller tell a request
 * that needs a ceremony apart from a transport or protocol failure.
 */
const INTERACTION_REQUIRED_CODE = 3002;

/**
 * Internet Identity had nothing to answer a silent request from.
 *
 * The one denial that is not a failure: it says a ceremony is needed, so the
 * caller signs in interactively rather than retrying. It is also the only
 * dependable evidence that a shared record is stale rather than replaced, which
 * is what lets an origin retract a record it did not write.
 *
 * Thrown only for a request that asked not to render anything. An interactive
 * sign-in that the user abandons is a different outcome and is not this.
 */
export class InteractionRequiredError extends Error {
  /**
   * Why, where Internet Identity said: `login_required` where it holds no
   * session, `account_selection_required` where it holds more than one and the
   * request named none.
   *
   * A caller may word its prompt from this and does not have to branch on it, so
   * it is deliberately a string rather than a union — a value this library does
   * not know is not a reason to fail.
   */
  readonly reason: string | undefined;

  constructor(message: string, reason?: string) {
    super(message);
    this.name = 'InteractionRequiredError';
    this.reason = reason;
  }
}

interface SessionDelegationResult {
  publicKey: string;
  signerDelegation: {
    delegation: { pubkey: string; expiration: string; targets?: string[] };
    signature: string;
  }[];
}

const looksLikeResult = (value: unknown): value is SessionDelegationResult => {
  const result = value as SessionDelegationResult | undefined;
  return (
    typeof result?.publicKey === 'string' &&
    Array.isArray(result?.signerDelegation) &&
    // An empty list builds a chain whose earliest expiry is 0, so it reads as a
    // session that expired at the epoch rather than as a bad response.
    result.signerDelegation.length > 0
  );
};

/**
 * Asks the identity provider for a session, and returns the chain it signed.
 *
 * The chain is restricted to the Internet Identity canister, so it is not
 * something an application can call its own canisters with. It is what app
 * delegations are minted from.
 */
export async function requestSessionDelegation(
  signer: Signer,
  params: {
    sessionPublicKey: DerEncodedPublicKey;
    maxTimeToLive?: bigint;
    derivationOrigin?: string;
  },
): Promise<DelegationChain> {
  const response = await signer.sendRequest({
    jsonrpc: '2.0',
    id: globalThis.crypto.randomUUID(),
    method: SESSION_DELEGATION_METHOD,
    params: {
      sessionPublicKey: toBase64(params.sessionPublicKey),
      ...(params.maxTimeToLive === undefined
        ? {}
        : { maxTimeToLive: params.maxTimeToLive.toString() }),
      ...(params.derivationOrigin === undefined
        ? {}
        : { icrc95DerivationOrigin: params.derivationOrigin }),
    },
  });

  if ('error' in response) {
    // The code carries the only thing a caller can act on, and dropping it left
    // `interaction_required` indistinguishable from a transport failure except by
    // matching a message this library does not define.
    if (response.error.code === INTERACTION_REQUIRED_CODE) {
      const data = response.error.data;
      const reason =
        typeof data === 'object' && data !== null && 'reason' in data
          ? String((data as { reason: unknown }).reason)
          : undefined;
      throw new InteractionRequiredError(response.error.message, reason);
    }
    throw new Error(response.error.message);
  }

  const result = response.result;
  if (!looksLikeResult(result)) {
    throw new Error(
      'Invalid session response: missing publicKey, or missing or empty signerDelegation',
    );
  }

  return DelegationChain.fromDelegations(
    result.signerDelegation.map(({ delegation, signature }) => ({
      delegation: new Delegation(
        fromBase64(delegation.pubkey),
        BigInt(delegation.expiration),
        delegation.targets?.map((target) => Principal.fromText(target)),
      ),
      signature: fromBase64(signature) as DelegationChain['delegations'][number]['signature'],
    })),
    fromBase64(result.publicKey) as DerEncodedPublicKey,
  );
}
