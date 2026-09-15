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
    maxTimeToIdle?: bigint;
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
      ...(params.maxTimeToIdle === undefined
        ? {}
        : { maxTimeToIdle: params.maxTimeToIdle.toString() }),
      ...(params.derivationOrigin === undefined
        ? {}
        : { icrc95DerivationOrigin: params.derivationOrigin }),
    },
  });

  if ('error' in response) {
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
