import { Delegation, DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { describe, expect, it } from 'vitest';

import { SessionGoneError } from '../../src/client/app-delegation-source.ts';
import {
  appDelegationChain,
  assertChainReaches,
  unwrapSessionResult,
} from '../../src/client/session-minter.ts';

const II = Principal.fromText('rdmx6-jaaaa-aaaaa-aaadq-cai');
const OTHER = Principal.fromText('rrkah-fqaaa-aaaaa-aaaaq-cai');

const accountKey = Ed25519KeyIdentity.generate();

function chainTargeting(...perHop: Principal[][]): DelegationChain {
  return DelegationChain.fromDelegations(
    perHop.map((targets) => ({
      delegation: new Delegation(
        Ed25519KeyIdentity.generate().getPublicKey().toDer(),
        1_700_000_000_000_000_000n,
        targets.length > 0 ? targets : undefined,
      ),
      signature: new Uint8Array([1]) as DelegationChain['delegations'][number]['signature'],
    })),
    accountKey.getPublicKey().toDer(),
  );
}

const signed = (
  over: Partial<{ permissions: [] | [string]; targets: [] | [Principal[]] }> = {},
) => ({
  delegation: {
    pubkey: Ed25519KeyIdentity.generate().getPublicKey().toDer(),
    expiration: 1_700_000_000_000_000_000n,
    targets: over.targets ?? ([] as []),
    permissions: over.permissions ?? ([] as []),
  },
  signature: new Uint8Array([1, 2, 3]),
});

describe('unwrapSessionResult', () => {
  it('returns the value', () => {
    expect(unwrapSessionResult({ Ok: 42 })).toBe(42);
  });

  it('turns NoMatchingSession into the one terminal error', () => {
    expect(() => unwrapSessionResult({ Err: { NoMatchingSession: null } })).toThrow(
      SessionGoneError,
    );
  });

  it('leaves any other failure retryable', () => {
    let thrown: unknown;
    try {
      unwrapSessionResult({ Err: { InternalCanisterError: 'out of cycles' } });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect(thrown).not.toBeInstanceOf(SessionGoneError);
    // The canister's own explanation, not "[object Object]".
    expect((thrown as Error).message).toContain('out of cycles');
  });
});

describe('appDelegationChain', () => {
  it('roots the chain at the account key the canister returned', () => {
    const userKey = accountKey.getPublicKey().toDer();
    const chain = appDelegationChain(userKey, signed());

    expect(chain.publicKey).toEqual(userKey);
    expect(chain.delegations).toHaveLength(1);
  });

  it('carries the expiration the canister signed', () => {
    const chain = appDelegationChain(accountKey.getPublicKey().toDer(), signed());
    expect(chain.delegations[0].delegation.expiration).toBe(1_700_000_000_000_000_000n);
  });

  it('leaves an app delegation unrestricted', () => {
    const chain = appDelegationChain(accountKey.getPublicKey().toDer(), signed());
    expect(chain.delegations[0].delegation.targets).toBeUndefined();
  });

  it('refuses a read-only session rather than dropping its permissions', () => {
    expect(() =>
      appDelegationChain(accountKey.getPublicKey().toDer(), signed({ permissions: ['queries'] })),
    ).toThrow(/read-only/);
  });
});

describe('assertChainReaches', () => {
  it('accepts a chain restricted to the canister being called', () => {
    expect(() => assertChainReaches(chainTargeting([II]), II)).not.toThrow();
  });

  it('accepts the same canister named by every hop', () => {
    expect(() => assertChainReaches(chainTargeting([II], [II]), II)).not.toThrow();
  });

  it('refuses an unrestricted chain, which could sign any call', () => {
    expect(() => assertChainReaches(chainTargeting([]), II)).toThrow(/names nothing/);
  });

  it('refuses a chain naming another canister alongside this one', () => {
    expect(() => assertChainReaches(chainTargeting([II, OTHER]), II)).toThrow(
      /must be restricted to/,
    );
  });

  it('refuses a chain restricted elsewhere, which is a misconfigured canister id', () => {
    expect(() => assertChainReaches(chainTargeting([OTHER]), II)).toThrow(
      new RegExp(`restricted to ${II.toText()}, but this one names ${OTHER.toText()}`),
    );
  });
});
