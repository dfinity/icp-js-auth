import { Delegation, DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { describe, expect, it, vi } from 'vitest';

import { SessionGoneError } from '../../src/client/app-delegation-source.ts';
import {
  appDelegationChain,
  assertChainReaches,
  SessionMinter,
  unwrapSessionResult,
} from '../../src/client/session-minter.ts';

const II = Principal.fromText('rdmx6-jaaaa-aaaaa-aaadq-cai');
const OTHER = Principal.fromText('rrkah-fqaaa-aaaaa-aaaaq-cai');

const accountKey = Ed25519KeyIdentity.generate();

/// `undefined` is a hop that restricts nothing; `[]` is one that names nothing.
/// The two are different chains, so this passes them through as given rather
/// than folding one into the other.
function chainTargeting(...perHop: (Principal[] | undefined)[]): DelegationChain {
  return DelegationChain.fromDelegations(
    perHop.map((targets) => ({
      delegation: new Delegation(
        Ed25519KeyIdentity.generate().getPublicKey().toDer(),
        1_700_000_000_000_000_000n,
        targets,
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

  it('turns NoSuchSession into the one terminal error', () => {
    expect(() => unwrapSessionResult({ Err: { NoSuchSession: null } })).toThrow(SessionGoneError);
  });

  // The session is live, so the remedy is another prepare rather than another
  // sign-in, and telling the two apart is what lets `mint` retry.
  it('keeps NoSuchDelegation apart from a session that is gone', () => {
    let thrown: unknown;
    try {
      unwrapSessionResult({ Err: { NoSuchDelegation: null } });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect(thrown).not.toBeInstanceOf(SessionGoneError);
    expect((thrown as Error).name).toBe('NoSuchDelegationError');
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

  it('leaves an app delegation without permissions', () => {
    const chain = appDelegationChain(accountKey.getPublicKey().toDer(), signed());
    expect(chain.delegations[0].delegation.permissions).toBeUndefined();
  });

  it('carries the permissions of a read-only session', () => {
    const chain = appDelegationChain(
      accountKey.getPublicKey().toDer(),
      signed({ permissions: ['queries'] }),
    );
    expect(chain.delegations[0].delegation.permissions).toBe('queries');
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
    expect(() => assertChainReaches(chainTargeting(undefined), II)).toThrow(
      /no hop of this one names any canister/,
    );
  });

  it('refuses a hop naming nothing, which can call nothing', () => {
    expect(() => assertChainReaches(chainTargeting([]), II)).toThrow(/names nothing/);
  });

  it('accepts the shape the identity provider issues', () => {
    // The canister signs an unrestricted hop to the provider's own key, and the
    // provider's extension to the application's key is what names the canister.
    // The effective restriction is the intersection, so this reaches II alone.
    expect(() => assertChainReaches(chainTargeting(undefined, [II]), II)).not.toThrow();
  });

  it('refuses a chain naming another canister alongside this one', () => {
    expect(() => assertChainReaches(chainTargeting([II, OTHER]), II)).toThrow(
      new RegExp(`also names ${OTHER.toText()}`),
    );
  });

  it('refuses a chain restricted elsewhere, which is a misconfigured canister id', () => {
    expect(() => assertChainReaches(chainTargeting([OTHER]), II)).toThrow(
      new RegExp(`restricted to ${II.toText()}, but this one also names ${OTHER.toText()}`),
    );
  });

  it('refuses a hop that names nothing, even beside one that names the canister', () => {
    // `targets: []` names nothing, which is not the same as naming this canister.
    // Folding every hop's targets into one list would let the good hop cover for it.
    const chain = DelegationChain.fromDelegations(
      [
        {
          delegation: new Delegation(
            Ed25519KeyIdentity.generate().getPublicKey().toDer(),
            1_700_000_000_000_000_000n,
            [II],
          ),
          signature: new Uint8Array([1]) as DelegationChain['delegations'][number]['signature'],
        },
        {
          delegation: new Delegation(
            Ed25519KeyIdentity.generate().getPublicKey().toDer(),
            1_700_000_000_000_000_000n,
            [],
          ),
          signature: new Uint8Array([1]) as DelegationChain['delegations'][number]['signature'],
        },
      ],
      accountKey.getPublicKey().toDer(),
    );

    expect(() => assertChainReaches(chain, II)).toThrow(/must be restricted to/);
  });
});

describe('SessionMinter.mint', () => {
  // The constructor is private so nothing builds a minter without an agent, and
  // what the canister's answers make `mint` do needs no agent to test.
  const over = (service: unknown): SessionMinter =>
    new (SessionMinter as unknown as new (service: unknown) => SessionMinter)(service);

  const prepared = { Ok: { user_key: accountKey.getPublicKey().toDer(), expiration: 1n } };
  const appKey = Ed25519KeyIdentity.generate().getPublicKey().toDer();

  it('prepares again when the canister signed nothing for what it prepared', async () => {
    let gets = 0;
    const service = {
      app_prepare_delegation: vi.fn(async () => prepared),
      app_get_delegation: vi.fn(async () => {
        gets += 1;
        return gets === 1 ? { Err: { NoSuchDelegation: null } } : { Ok: signed() };
      }),
      app_revoke_session: vi.fn(async () => ({ Ok: null })),
    };

    await expect(over(service).mint(appKey)).resolves.toBeInstanceOf(DelegationChain);

    // The whole pair again, not just the fetch: a new expiration is the point.
    expect(service.app_prepare_delegation).toHaveBeenCalledTimes(2);
    expect(service.app_get_delegation).toHaveBeenCalledTimes(2);
  });

  it('gives up after the second attempt rather than pursuing it', async () => {
    const service = {
      app_prepare_delegation: vi.fn(async () => prepared),
      app_get_delegation: vi.fn(async () => ({ Err: { NoSuchDelegation: null } })),
      app_revoke_session: vi.fn(async () => ({ Ok: null })),
    };

    await expect(over(service).mint(appKey)).rejects.toThrow(/signed no delegation/);
    expect(service.app_prepare_delegation).toHaveBeenCalledTimes(2);
  });

  it('does not retry a session that is gone, which another prepare cannot fix', async () => {
    const service = {
      app_prepare_delegation: vi.fn(async () => ({ Err: { NoSuchSession: null } })),
      app_get_delegation: vi.fn(async () => ({ Ok: signed() })),
      app_revoke_session: vi.fn(async () => ({ Ok: null })),
    };

    await expect(over(service).mint(appKey)).rejects.toBeInstanceOf(SessionGoneError);
    expect(service.app_prepare_delegation).toHaveBeenCalledTimes(1);
  });

  it('raises a revoke the canister refused, rather than reporting it signed out', async () => {
    const service = {
      app_prepare_delegation: vi.fn(async () => prepared),
      app_get_delegation: vi.fn(async () => ({ Ok: signed() })),
      app_revoke_session: vi.fn(async () => ({
        Err: { InternalCanisterError: 'could not write' },
      })),
    };

    await expect(over(service).revoke()).rejects.toThrow(/could not write/);
  });

  it('treats a session already gone as a revoke that succeeded', async () => {
    const service = {
      app_prepare_delegation: vi.fn(async () => prepared),
      app_get_delegation: vi.fn(async () => ({ Ok: signed() })),
      app_revoke_session: vi.fn(async () => ({ Ok: null })),
    };

    await expect(over(service).revoke()).resolves.toBeUndefined();
  });
});
