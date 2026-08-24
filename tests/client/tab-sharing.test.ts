import type { PublicKey, SignIdentity } from '@icp-sdk/core/agent';
import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthClient } from '../../src/client/auth-client.ts';
import type { IdentityStorage } from '../../src/client/identity-storage.ts';
import type { SessionIdentity } from '../../src/client/session-identity.ts';
import type { Session, SessionStorage } from '../../src/client/session-storage.ts';
import { FakeTransport } from './fake-transport.ts';

// In-memory identity storage that records every identity it creates, so tests
// can assert on create/set/remove calls and compare generated identities. Uses
// Ed25519 (synchronous, deterministic) rather than the ECDSA default. create()
// only mints; set() persists, mirroring the real stores.
function createIdentityStorage(
  initial: SignIdentity | null = null,
): IdentityStorage & { created: SignIdentity[] } {
  const created: SignIdentity[] = [];
  let current: SignIdentity | null = initial;
  return {
    created,
    create: vi.fn(async () => {
      const identity = Ed25519KeyIdentity.generate();
      created.push(identity);
      return identity;
    }),
    set: vi.fn(async (identity: SignIdentity) => {
      current = identity;
    }),
    get: vi.fn(async () => current),
    remove: vi.fn(async () => {
      current = null;
    }),
  };
}

// In-memory delegation storage with spies on every method.
// Takes a chain rather than a Session so the tests below read as what they are
// about; the session wrapper is this helper's business.
function createSessionStorage(initial: DelegationChain | null = null): SessionStorage {
  let current: Session | null =
    initial === null ? null : { chain: initial, accountKey: initial.publicKey };
  return {
    get: vi.fn(() => current),
    set: vi.fn((session: Session) => {
      current = session;
    }),
    remove: vi.fn(() => {
      current = null;
    }),
    discard: vi.fn(() => {
      current = null;
    }),
    subscribe: vi.fn(() => () => {}),
  };
}

// A session storage whose change listener can be fired on demand, to simulate a
// sign-in or sign-out that happened in another tab or on a sibling origin.
// `external()` mutates the stored session and notifies the subscriber.

const II_CANISTER = Principal.fromText('rdmx6-jaaaa-aaaaa-aaadq-cai');

// Minting is a canister call, so the source is replaced rather than the network.
// The timing it drives is covered in session-identity.test.ts; what matters here
// is that AuthClient mints once at sign-in and stores what came back. The mock
// fills in `minted.accountKey` so assertions can name the principal it roots at.
const minted = vi.hoisted(() => ({
  accountKey: undefined as SignIdentity | undefined,
  count: 0,
  refuse: false,
  revoked: 0,
  revokeFails: false,
}));

vi.mock('../../src/client/session-minter.ts', async () => {
  const { DelegationChain: Chain, Ed25519KeyIdentity: Key } = await import(
    '@icp-sdk/core/identity'
  );
  const accountKey = Key.generate();
  minted.accountKey = accountKey;
  return {
    SessionMinter: {
      create: async () => ({
        mint: async (appPublicKey: Uint8Array) => {
          minted.count += 1;
          if (minted.refuse) {
            const { SessionGoneError } = await import('../../src/client/app-delegation-source.ts');
            throw new SessionGoneError();
          }
          return Chain.create(
            accountKey,
            { toDer: () => appPublicKey } as unknown as PublicKey,
            new Date(Date.now() + 5 * 60 * 1000),
          );
        },
        revoke: async () => {
          if (minted.revokeFails) throw new Error('offline');
          minted.revoked += 1;
        },
      }),
    },
  };
});

// Swap `PostMessageTransport` for `FakeTransport` so `AuthClient` uses the real
// `Signer` over an in-memory transport — no window is opened and nothing about
// the signer's JSON-RPC correlation is faked. `UrlTransport` is kept as the
// real export so the constructor's `instanceof UrlTransport` transport-select
// check behaves; redirect-flow tests replace it separately.
vi.mock('@icp-sdk/signer/web', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@icp-sdk/signer/web')>();
  const { FakeTransport } = await import('./fake-transport.ts');
  return { ...actual, PostMessageTransport: FakeTransport };
});

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function encodeDelegationChainResponse(chain: DelegationChain) {
  return {
    publicKey: toBase64(new Uint8Array(chain.publicKey)),
    signerDelegation: chain.delegations.map((sd) => ({
      delegation: {
        pubkey: toBase64(new Uint8Array(sd.delegation.pubkey)),
        expiration: sd.delegation.expiration.toString(),
        targets: sd.delegation.targets?.map((t) => t.toText()),
      },
      signature: toBase64(new Uint8Array(sd.signature)),
    })),
  };
}

type JsonRpcBody =
  | { result: unknown }
  | { error: { code: number; message: string; data?: unknown } };

// A session-chain response as Internet Identity builds it: a chain to the
// requested session key, restricted to the Internet Identity canister, and
// lasting as long as the session the user consented to.
async function conformantSignInBody(params: { sessionPublicKey: string }): Promise<JsonRpcBody> {
  const to = { toDer: () => fromBase64(params.sessionPublicKey) } as unknown as PublicKey;
  const chain = await DelegationChain.create(
    Ed25519KeyIdentity.generate(),
    to,
    new Date(Date.now() + 60 * 60 * 1000),
    { targets: [II_CANISTER] },
  );
  return { result: encodeDelegationChainResponse(chain) };
}

/**
 * Registers an `ii_session_delegation` handler. By default it returns a session
 * chain to the requested key; pass `body` to force a specific response.
 */
function handleSignIn(transport: FakeTransport, body?: JsonRpcBody): void {
  transport.onRequest(async (req) => {
    if (req.method !== 'ii_session_delegation') return;
    if (req.id === undefined || req.id === null) return;
    const resolved = body ?? (await conformantSignInBody(req.params as never));
    return { jsonrpc: '2.0', id: req.id, ...resolved };
  });
}

/**
 * Registers an `ii-icrc3-attributes` handler that returns the given body.
 * Defaults to a valid success response with placeholder data and signature.
 */

beforeEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  localStorage.clear();
  FakeTransport.reset();
  // `IdleManager.exit()` runs all registered callbacks on teardown (see
  // idle-manager.ts#exit), including the default `location.reload()` callback
  // from signed-in tests. Stub globally so afterEach teardown doesn't trigger
  // jsdom's "Not implemented: navigation to another Document" warning.
  vi.stubGlobal('location', { reload: vi.fn() });
});

/**
 * Its own file because every client here shares one channel: a client left alive
 * by another test is, from the channel's point of view, another tab of this
 * origin, and it answers asks with credentials for its own session.
 */
describe('tabs of one origin', () => {
  /** Lets pending work run until `changed()`, or a bounded number of turns. */
  const settle = async (changed: () => boolean): Promise<void> => {
    for (let turn = 0; turn < 50 && !changed(); turn++) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
  };

  it('a tab opening takes what another tab already has, and mints nothing', async () => {
    const identityStorage = createIdentityStorage();
    const sessionStorage = createSessionStorage();
    const first = new AuthClient({ identityStorage, sessionStorage });
    handleSignIn(FakeTransport.last());
    const held = ((await first.signIn()) as SessionIdentity).getDelegation();
    minted.count = 0;

    // A second client over the same storage is another tab of this origin. It
    // asks on the channel, and the first answers.
    const second = new AuthClient({ identityStorage, sessionStorage });
    const identity = await second.getIdentity();

    expect((identity as SessionIdentity).getDelegation().toJSON()).toEqual(held.toJSON());
    expect(minted.count).toBe(0);
    first.dispose();
    second.dispose();
  });

  it('a tab opening alone mints, rather than waiting for an answer that is not coming', async () => {
    const identityStorage = createIdentityStorage();
    const sessionStorage = createSessionStorage();
    const first = new AuthClient({ identityStorage, sessionStorage });
    handleSignIn(FakeTransport.last());
    await first.signIn();
    // The tab that could answer is gone.
    first.dispose();
    minted.count = 0;

    const second = new AuthClient({ identityStorage, sessionStorage });
    await second.getIdentity();
    await (await second.getIdentity()).transformRequest({
      body: { arg: new Uint8Array() },
    } as never);

    expect(minted.count).toBe(1);
    second.dispose();
  });

  it('offers what it mints, so the other tabs do not spend a call on it', async () => {
    const identityStorage = createIdentityStorage();
    const sessionStorage = createSessionStorage();
    const a = new AuthClient({ identityStorage, sessionStorage });
    handleSignIn(FakeTransport.last());
    const identityA = (await a.signIn()) as SessionIdentity;

    const b = new AuthClient({ identityStorage, sessionStorage });
    const identityB = (await b.getIdentity()) as SessionIdentity;
    minted.count = 0;

    // A's credential has to be worth replacing first, or refresh() correctly does
    // nothing: the clock moves past the pre-mint threshold without its own timers
    // running, as a backgrounded tab's would not.
    vi.useFakeTimers();
    vi.setSystemTime(new Date(Date.now() + 4 * 60 * 1000 + 50_000));

    // A mints a replacement; B should end up holding the same one.
    await identityA.refresh();
    // Real timers again, so the channel can deliver what A just offered.
    vi.useRealTimers();
    await settle(() => identityB.getDelegation().toJSON() === identityA.getDelegation().toJSON());

    expect(identityB.getDelegation().toJSON()).toEqual(identityA.getDelegation().toJSON());
    expect(minted.count).toBe(1);
    a.dispose();
    b.dispose();
  });
});
