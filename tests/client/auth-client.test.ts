import type { PublicKey, SignIdentity } from '@icp-sdk/core/agent';
import {
  DelegationChain,
  type DelegationIdentity,
  Ed25519KeyIdentity,
} from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthClient } from '../../src/client/auth-client.ts';
import type { Credential, CredentialStorage } from '../../src/client/credential-storage.ts';
import { IdbCredentialStorage } from '../../src/client/idb-credential-storage.ts';
import { IdleManager } from '../../src/client/idle-manager.ts';
import { MemoryCredentialStorage } from '../../src/client/memory-credential-storage.ts';
import { slotsFor } from '../../src/client/slots.ts';
import { MemoryStateStorage } from '../../src/client/state-storage.ts';
import { FakeTransport } from './fake-transport.ts';

/** The bare names, which is what a client with no namespace writes under. */
const SLOTS = slotsFor();

const II_CANISTER = Principal.fromText('rdmx6-jaaaa-aaaaa-aaadq-cai');

// Minting is a canister call, so the source is replaced rather than the network.
// The timing it drives is covered in session-identity.test.ts; what matters here
// is that AuthClient mints at sign-in and stores what came back. The mock fills
// in `minted.accountKey` so assertions can name the principal it roots at.
const minted = vi.hoisted(() => ({
  accountKey: undefined as SignIdentity | undefined,
  createdWith: [] as { canisterId?: unknown; agentOptions?: unknown }[],
  count: 0,
  revoked: 0,
  refuse: false,
}));

vi.mock('../../src/client/session-minter.ts', async () => {
  const { DelegationChain: Chain, Ed25519KeyIdentity: Key } = await import(
    '@icp-sdk/core/identity'
  );
  const accountKey = Key.generate();
  minted.accountKey = accountKey;
  return {
    SessionMinter: {
      create: async (options: { canisterId?: unknown; agentOptions?: unknown }) => ({
        mint: async (appPublicKey: Uint8Array) => {
          minted.createdWith.push({
            canisterId: options.canisterId,
            agentOptions: options.agentOptions,
          });
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

// A credential store backed by memory, with every call recorded, so a test can
// assert what was written without reaching into an implementation's internals.
function spyStorage(seed?: Credential): CredentialStorage & {
  writes: { slot: string; credential: Credential }[];
} {
  const inner = new MemoryCredentialStorage();
  const writes: { slot: string; credential: Credential }[] = [];
  const storage = {
    shared: inner.shared,
    durable: inner.durable,
    writes,
    create: () => inner.create(),
    get: (slot: string) => inner.get(slot),
    set: vi.fn(async (slot: string, credential: Credential) => {
      writes.push({ slot, credential });
      await inner.set(slot, credential as never);
    }),
    remove: vi.fn((slot: string) => inner.remove(slot)),
  };
  if (seed) void inner.set(SLOTS.session, seed as never);
  return storage;
}

// The state a stored chain puts an origin in, so a test that seeds storage
// directly seeds what AuthClient reads to decide it is signed in.
function stateFor(chain: DelegationChain): MemoryStateStorage {
  const storage = new MemoryStateStorage();
  storage.set({
    principal: Principal.selfAuthenticating(new Uint8Array(chain.publicKey)),
    expiration: chain.delegations[0]!.delegation.expiration,
  });
  return storage;
}

async function createTestDelegation(key: Ed25519KeyIdentity, expiration?: Date) {
  const exp = expiration ?? new Date(Date.now() + 24 * 60 * 60 * 1000); // 1 day from now
  return DelegationChain.create(key, key.getPublicKey(), exp);
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

const DEFAULT_REQUEST_ATTRIBUTES_BODY: JsonRpcBody = {
  result: { data: btoa('hello'), signature: btoa('sig') },
};

// A session-chain response as Internet Identity builds it: a chain to the
// requested session key, restricted to the Internet Identity canister, and
// lasting as long as the session the user consented to.
async function conformantSignInBody(params: {
  sessionPublicKey: string;
  maxTimeToLive?: string;
}): Promise<JsonRpcBody> {
  const to = { toDer: () => fromBase64(params.sessionPublicKey) } as unknown as PublicKey;
  const ttlMs =
    params.maxTimeToLive !== undefined
      ? Number(BigInt(params.maxTimeToLive) / 1_000_000n)
      : 60 * 60 * 1000;
  const chain = await DelegationChain.create(
    Ed25519KeyIdentity.generate(),
    to,
    new Date(Date.now() + ttlMs),
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
function handleRequestAttributes(
  transport: FakeTransport,
  body: JsonRpcBody = DEFAULT_REQUEST_ATTRIBUTES_BODY,
): void {
  transport.onRequest((req) => {
    if (req.method !== 'ii-icrc3-attributes') return;
    if (req.id === undefined || req.id === null) return;
    return { jsonrpc: '2.0', id: req.id, ...body };
  });
}

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

afterEach(async () => {
  // IdleManager is a singleton — without tearing it down, idle timers and DOM
  // listeners from one test bleed into the next, causing spurious failures.
  try {
    IdleManager.create().exit();
  } catch {
    // no-op if already torn down
  }
  await new Promise((r) => setTimeout(r, 0));
  localStorage.clear();
});

describe('AuthClient', () => {
  it('should initialize with an AnonymousIdentity', async () => {
    const client = new AuthClient();
    expect(client.isAuthenticated()).toBe(false);
    const identity = await client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(true);
  });

  it('should use a provided identity as the key for hydration', async () => {
    const identity = Ed25519KeyIdentity.generate();
    const chain = await createTestDelegation(identity);
    const client = new AuthClient({
      identity,
      credentialStorage: spyStorage({ identity, chain }),
      stateStorage: stateFor(chain),
    });
    const resolved = await client.getIdentity();
    expect(resolved.getPrincipal().isAnonymous()).toBe(false);
  });

  it('stops claiming a sign-in it has nothing left to restore', async () => {
    // A record naming a sign-in with nothing behind it: a credential store
    // cleared on its own, or one that does not survive a reload paired with a
    // state that does.
    const stateStorage = new MemoryStateStorage();
    stateStorage.set({
      principal: Principal.selfAuthenticating(new Uint8Array([1, 2, 3])),
      expiration: (BigInt(Date.now()) + 3_600_000n) * 1_000_000n,
    });
    const client = new AuthClient({ credentialStorage: spyStorage(), stateStorage });
    await client.getIdentity();

    // Saying "signed in" with nothing to act with is what the state leading forbids.
    expect(stateStorage.get()).toBeNull();
    expect(client.isAuthenticated()).toBe(false);
  });

  it.each([
    ['signed-out', null, false],
    ['signed-in', { held: true, ms: 3_600_000 }, true],
    ['signed-in-elsewhere', { held: false, ms: 3_600_000 }, false],
    ['expired', { held: true, ms: -1000 }, false],
  ] as const)('reports %s', (expected, shape, authenticated) => {
    const principal = Principal.selfAuthenticating(new Uint8Array([1, 2, 3]));
    const stateStorage = {
      get: () =>
        shape === null
          ? null
          : {
              principal,
              expiration: (BigInt(Date.now()) + BigInt(shape.ms)) * 1_000_000n,
              held: shape.held,
            },
      set: vi.fn(),
      remove: vi.fn(),
    };

    const client = new AuthClient({ stateStorage, idleOptions: { disableIdle: true } });

    expect(client.getStatus().status).toBe(expected);
    // The predicate is the same rule, so the two can never disagree.
    expect(client.isAuthenticated()).toBe(authenticated);
  });

  it('carries the account in every case where a record exists', () => {
    const principal = Principal.selfAuthenticating(new Uint8Array([1, 2, 3]));
    const stateStorage = {
      get: () => ({
        principal,
        expiration: (BigInt(Date.now()) - 1_000n) * 1_000_000n,
        held: false,
      }),
      set: vi.fn(),
      remove: vi.fn(),
    };

    const status = new AuthClient({ stateStorage, idleOptions: { disableIdle: true } }).getStatus();

    // A silent re-issue needs it to name the account, so the type carries it
    // wherever there is one to carry.
    expect(status.status === 'signed-out' ? null : status.principal).toEqual(principal);
  });

  it('is not authenticated by a record this origin does not hold', async () => {
    // What a store whose record reaches further than one origin reports on an
    // origin that has not acquired a credential of its own.
    const stateStorage = {
      get: () => ({
        principal: Principal.selfAuthenticating(new Uint8Array([1, 2, 3])),
        expiration: (BigInt(Date.now()) + 3_600_000n) * 1_000_000n,
        held: false,
      }),
      set: vi.fn(),
      remove: vi.fn(),
    };

    const client = new AuthClient({ stateStorage, idleOptions: { disableIdle: true } });

    // Someone is signed in within that store's reach; this origin cannot act.
    expect(stateStorage.get()).not.toBeNull();
    expect(client.isAuthenticated()).toBe(false);
  });

  it('keeps two clients under one origin apart when they are namespaced', async () => {
    const credentialStorage = new MemoryCredentialStorage();
    const first = new AuthClient({ credentialStorage, namespace: 'one' });
    handleSignIn(FakeTransport.last());
    await first.signIn();

    // Same store, different namespace: the second client writes elsewhere and
    // finds nothing of the first's.
    const second = new AuthClient({ credentialStorage, namespace: 'two' });
    const identity = await second.getIdentity();

    expect(identity.getPrincipal().isAnonymous()).toBe(true);
    expect(await credentialStorage.get('one:session')).not.toBeNull();
    expect(await credentialStorage.get('two:session')).toBeNull();
    // The record of who is signed in moves with the slots. Leaving it fixed gave
    // two namespaced clients their own credentials and one shared answer to who
    // was signed in, which is the half a namespace exists to prevent.
    expect(localStorage.getItem('one:ic-session-state')).not.toBeNull();
    expect(localStorage.getItem('ic-session-state')).toBeNull();
  });

  it('keeps a namespaced sign-in wholly inside its namespace', async () => {
    const credentialStorage = new MemoryCredentialStorage();
    const client = new AuthClient({
      credentialStorage,
      namespace: 'one',
      idleOptions: { disableIdle: true },
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    // Every name the sign-in touches carries the prefix. A bare one left behind
    // is a credential the client never reads and never clears: the identity
    // would mint again on the next load, and sign-out would miss it.
    expect(await credentialStorage.get('one:session')).not.toBeNull();
    expect(await credentialStorage.get('one:app')).not.toBeNull();
    expect(await credentialStorage.get(SESSION_SLOT)).toBeNull();
    expect(await credentialStorage.get(APP_SLOT)).toBeNull();

    await client.signOut();

    expect(await credentialStorage.get('one:session')).toBeNull();
    expect(await credentialStorage.get('one:app')).toBeNull();
  });

  it('refuses the identity provider as a bare URL, which it used to be', () => {
    // Silently ignored would mean both halves falling back to mainnet.
    expect(() => new AuthClient({ identityProvider: 'https://id.ai/authorize' as never })).toThrow(
      TypeError,
    );
    expect(
      () => new AuthClient({ identityProvider: new URL('https://id.ai/authorize') as never }),
    ).toThrow(TypeError);
  });

  it('should sign users out', async () => {
    const client = new AuthClient();
    await client.signOut();
    expect(client.isAuthenticated()).toBe(false);
    const identity = await client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(true);
  });

  it('navigates to a same-origin returnTo on sign out', async () => {
    vi.stubGlobal('location', {
      reload: vi.fn(),
      href: 'http://localhost/app',
      origin: 'http://localhost',
    });
    const client = new AuthClient();
    const pushState = vi.spyOn(window.history, 'pushState').mockImplementation(() => {});
    await client.signOut({ returnTo: '/logged-out' });
    expect(pushState).toHaveBeenCalledWith({}, '', 'http://localhost/logged-out');
    pushState.mockRestore();
  });

  it('falls back to a location navigation to the validated target when pushState throws', async () => {
    vi.stubGlobal('location', {
      reload: vi.fn(),
      href: 'http://localhost/app',
      origin: 'http://localhost',
    });
    const client = new AuthClient();
    const pushState = vi.spyOn(window.history, 'pushState').mockImplementation(() => {
      throw new Error('pushState unavailable');
    });
    await client.signOut({ returnTo: '/logged-out' });
    // Fallback navigates to the resolved, validated same-origin URL — never the raw string.
    expect(window.location.href).toBe('http://localhost/logged-out');
    pushState.mockRestore();
  });

  it('refuses a cross-origin, protocol-relative, or javascript: returnTo', async () => {
    // A concrete same-origin location so `//evil.example` resolves (to
    // http://evil.example/) and is rejected on the origin check — not because
    // the base is undefined.
    vi.stubGlobal('location', {
      reload: vi.fn(),
      href: 'http://localhost/app',
      origin: 'http://localhost',
    });
    const client = new AuthClient();
    const pushState = vi.spyOn(window.history, 'pushState');
    for (const returnTo of [
      'https://evil.example/phish',
      '//evil.example',
      'javascript:fetch("https://evil.example/" + document.cookie)',
    ]) {
      await client.signOut({ returnTo });
    }
    // Neither sink is reached: no history entry, and the location.href fallback
    // never navigated away from the current page.
    expect(pushState).not.toHaveBeenCalled();
    expect(window.location.href).toBe('http://localhost/app');
    pushState.mockRestore();
  });

  it('should not initialize an idleManager if the user is not signed in', async () => {
    const client = new AuthClient();
    await client.getIdentity(); // wait for hydration
    expect(client.idleManager).toBeUndefined();
  });

  it.each([
    ['google', 'https://accounts.google.com'],
    ['apple', 'https://appleid.apple.com'],
    ['microsoft', 'https://login.microsoftonline.com/{tid}/v2.0'],
  ] as const)('should pass openid=%s search param to the transport', (provider, expectedUrl) => {
    new AuthClient({ openIdProvider: provider });
    const url = new URL(FakeTransport.last().options.url ?? '');
    expect(url.searchParams.get('openid')).toBe(expectedUrl);
  });

  it('should not include openid search param when openIdProvider is not set', () => {
    new AuthClient();
    const url = new URL(FakeTransport.last().options.url ?? '');
    expect(url.searchParams.has('openid')).toBe(false);
  });

  it('should forward windowOpenerFeatures to the transport', () => {
    new AuthClient({ windowOpenerFeatures: 'width=500,height=600' });
    expect(FakeTransport.last().options.windowOpenerFeatures).toBe('width=500,height=600');
  });

  it('should not set up an idle timer if the disable option is set', () => {
    const client = new AuthClient({
      idleOptions: {
        idleTimeout: 1000,
        disableIdle: true,
      },
    });
    expect(client.idleManager).toBeUndefined();
  });

  it('memoize runs the producer and returns its value in window mode', async () => {
    const client = new AuthClient(); // default 'window' transport
    const produce = vi.fn(async () => 'value');

    expect(await client.memoize(produce)).toBe('value');
    expect(produce).toHaveBeenCalledOnce();
  });
});

describe('AuthClient signIn', () => {
  it('should return the authenticated identity', async () => {
    const client = new AuthClient();
    handleSignIn(FakeTransport.last());
    const identity = await client.signIn();
    expect(identity.getPrincipal().toString()).toBeTruthy();
  });

  it('should set up an idle manager after sign-in', async () => {
    const client = new AuthClient();
    handleSignIn(FakeTransport.last());
    await client.signIn();
    expect(client.idleManager).toBeDefined();
  });

  it('should not set up an idle manager if disableIdle is set', async () => {
    const client = new AuthClient({ idleOptions: { disableIdle: true } });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    expect(client.idleManager).toBeUndefined();
  });

  it('should propagate signer errors from the delegation request', async () => {
    const client = new AuthClient();
    handleSignIn(FakeTransport.last(), {
      error: { code: -1, message: 'connection failed' },
    });
    await expect(client.signIn()).rejects.toThrow('connection failed');
  });

  it('asks for a session, carrying maxTimeToLive and no targets', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleSignIn(transport);

    await client.signIn({ maxTimeToLive: 1_000_000n });

    const req = transport.requests[0];
    expect(req.method).toBe('ii_session_delegation');
    expect(req.params?.sessionPublicKey).toEqual(expect.any(String));
    expect(req.params?.maxTimeToLive).toBe('1000000');
    // A session chain is restricted to Internet Identity, so an application has
    // no targets to ask for: what it may call is decided by the delegations
    // minted from the session, not by the session itself.
    expect(req.params?.targets).toBeUndefined();
  });

  it('should forward derivationOrigin on every request as icrc95DerivationOrigin', async () => {
    const client = new AuthClient({ derivationOrigin: 'https://example.com' });
    const transport = FakeTransport.last();
    handleSignIn(transport);

    await client.signIn();

    expect(transport.requests[0].params?.icrc95DerivationOrigin).toBe('https://example.com');
  });

  it('should persist the key and its delegation as one record after sign-in', async () => {
    const storage = spyStorage();
    const client = new AuthClient({ credentialStorage: storage });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    const session = storage.writes.filter((write) => write.slot === SLOTS.session);
    expect(session).toHaveLength(1);
    expect(session[0]?.credential.identity).toBeDefined();
    expect(session[0]?.credential.chain).toBeDefined();
  });

  it('should generate a fresh key for each sign-in', async () => {
    const storage = spyStorage();
    const client = new AuthClient({ credentialStorage: storage });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    await client.signIn();

    const keys = storage.writes
      .filter((write) => write.slot === SLOTS.session)
      .map((write) => write.credential.identity.getPublicKey().toDer().toString());
    expect(keys).toHaveLength(2);
    expect(keys[0]).not.toEqual(keys[1]);
  });

  it('should report the user as authenticated after sign-in', async () => {
    const client = new AuthClient({ idleOptions: { disableIdle: true } });
    handleSignIn(FakeTransport.last());
    expect(client.isAuthenticated()).toBe(false);
    await client.signIn();
    expect(client.isAuthenticated()).toBe(true);
  });

  it('should report the user as not authenticated after sign-out', async () => {
    const client = new AuthClient({ idleOptions: { disableIdle: true } });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    expect(client.isAuthenticated()).toBe(true);
    await client.signOut();
    expect(client.isAuthenticated()).toBe(false);
  });

  it('records the account and the expiry in the supplied state storage', async () => {
    const stateStorage = new MemoryStateStorage();
    const client = new AuthClient({ stateStorage, idleOptions: { disableIdle: true } });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    const state = stateStorage.get();
    const identity = await client.getIdentity();
    expect(state?.principal.toText()).toBe(identity.getPrincipal().toText());
    expect(state?.expiration).toBeGreaterThan(BigInt(Date.now()) * BigInt(1_000_000));
  });

  it('names who is signed in synchronously, from the state', () => {
    const stateStorage = new MemoryStateStorage();
    const principal = Principal.selfAuthenticating(new Uint8Array([1, 2, 3]));
    stateStorage.set({ principal, expiration: BigInt(Date.now() + 60_000) * 1_000_000n });
    const client = new AuthClient({ stateStorage, idleOptions: { disableIdle: true } });

    // No await, no store opened, no mint: this is the answer a page renders on.
    expect(client.getPrincipal()?.toText()).toBe(principal.toText());
  });

  it('names nobody when no record exists', () => {
    const client = new AuthClient({
      stateStorage: new MemoryStateStorage(),
      idleOptions: { disableIdle: true },
    });
    expect(client.getPrincipal()).toBeUndefined();
  });

  it('names nobody for a session that has expired, and agrees with isAuthenticated', () => {
    const stateStorage = new MemoryStateStorage();
    const principal = Principal.selfAuthenticating(new Uint8Array([4, 5, 6]));
    stateStorage.set({ principal, expiration: BigInt(Date.now() - 60_000) * 1_000_000n });
    const client = new AuthClient({ stateStorage, idleOptions: { disableIdle: true } });

    // A principal here means calls made as it will be accepted. `if
    // (getPrincipal())` is the check an application reaches for, so answering for
    // a session that has ended would have it act on one.
    expect(client.getPrincipal()).toBeUndefined();
    expect(client.isAuthenticated()).toBe(false);

    // Nothing is lost: getStatus() carries the account, with the status attached
    // so it cannot be mistaken for permission to act.
    const status = client.getStatus();
    expect(status.status).toBe('expired');
    expect(status.status !== 'signed-out' && status.principal.toText()).toBe(principal.toText());
  });

  it('never disagrees with isAuthenticated', () => {
    const stateStorage = new MemoryStateStorage();
    const client = new AuthClient({ stateStorage, idleOptions: { disableIdle: true } });
    const principal = Principal.selfAuthenticating(new Uint8Array([7, 8, 9]));

    for (const expiration of [
      BigInt(Date.now() + 60_000) * 1_000_000n,
      BigInt(Date.now() - 60_000) * 1_000_000n,
    ]) {
      stateStorage.set({ principal, expiration });
      // One predicate, two return types. They are the same question, so an
      // application cannot get a principal it is not allowed to act as.
      expect(client.getPrincipal() !== undefined).toBe(client.isAuthenticated());
    }

    stateStorage.remove();
    expect(client.getPrincipal() !== undefined).toBe(client.isAuthenticated());
  });

  it('answers isAuthenticated from the state storage and not from the delegation', async () => {
    const stateStorage = new MemoryStateStorage();
    const client = new AuthClient({ stateStorage, idleOptions: { disableIdle: true } });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    expect(client.isAuthenticated()).toBe(true);

    // The delegation is untouched; only the state is gone.
    stateStorage.remove();

    expect(client.isAuthenticated()).toBe(false);
  });

  it('restores a session and adopts the app credential rather than minting again', async () => {
    const credentialStorage = new IdbCredentialStorage();
    const stateStorage = new MemoryStateStorage();
    const first = new AuthClient({
      credentialStorage,
      stateStorage,
      idleOptions: { disableIdle: true },
    });
    handleSignIn(FakeTransport.last());
    await first.signIn();
    const after = minted.count;

    const second = new AuthClient({
      credentialStorage,
      stateStorage,
      idleOptions: { disableIdle: true },
    });
    const identity = await second.getIdentity();

    expect(identity.getPrincipal().isAnonymous()).toBe(false);
    expect(minted.count).toBe(after); // what was stored was enough
  });

  it('mints on a load that finds no app credential, which is where the account comes from', async () => {
    const credentialStorage = new IdbCredentialStorage();
    const stateStorage = new MemoryStateStorage();
    const first = new AuthClient({
      credentialStorage,
      stateStorage,
      idleOptions: { disableIdle: true },
    });
    handleSignIn(FakeTransport.last());
    await first.signIn();

    // As TAB-5 leaves things once a delegation has run out.
    await credentialStorage.remove(SLOTS.app);
    const after = minted.count;

    const second = new AuthClient({
      credentialStorage,
      stateStorage,
      idleOptions: { disableIdle: true },
    });
    const identity = await second.getIdentity();

    expect(minted.count).toBe(after + 1);
    expect(identity.getPrincipal().isAnonymous()).toBe(false);
  });

  it('does not restore a session the state does not back, and drops it', async () => {
    const credentialStorage = new IdbCredentialStorage();
    const stateStorage = new MemoryStateStorage();
    const first = new AuthClient({
      credentialStorage,
      stateStorage,
      idleOptions: { disableIdle: true },
    });
    handleSignIn(FakeTransport.last());
    await first.signIn();
    expect(await credentialStorage.get(SLOTS.session)).not.toBeNull();

    // Only the state goes; the credential is left exactly where it was.
    stateStorage.remove();

    const second = new AuthClient({
      credentialStorage,
      stateStorage,
      idleOptions: { disableIdle: true },
    });
    const identity = await second.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(true);
    expect(await credentialStorage.get(SLOTS.session)).toBeNull();
  });

  it('mints inside the ceremony, so the identity it returns already holds one', async () => {
    const storage = spyStorage();
    const client = new AuthClient({
      credentialStorage: storage,
      idleOptions: { disableIdle: true },
    });
    handleSignIn(FakeTransport.last());

    const before = minted.count;
    const identity = (await client.signIn()) as DelegationIdentity;

    // A delta: the counter is shared across this file, so an absolute number
    // would pass on mints another test made.
    expect(minted.count).toBe(before + 1);
    expect(identity.getDelegation().delegations).toHaveLength(1);
    expect(await storage.get(SLOTS.app)).not.toBeNull();
  });

  it('records the account the mint reported, not the session chain it was signed with', async () => {
    const stateStorage = new MemoryStateStorage();
    const client = new AuthClient({ stateStorage, idleOptions: { disableIdle: true } });
    handleSignIn(FakeTransport.last());

    const identity = await client.signIn();

    // The session chain is rooted at the session's own key; only a mint reports
    // the key an application's canisters see.
    const accountDer = minted.accountKey?.getPublicKey().toDer();
    const account = Principal.selfAuthenticating(new Uint8Array(accountDer ?? []));
    expect(stateStorage.get()?.principal.toText()).toBe(account.toText());
    expect(identity.getPrincipal().toText()).toBe(account.toText());
  });

  it('refuses a session chain issued to a different key', async () => {
    const client = new AuthClient({ idleOptions: { disableIdle: true } });
    const other = Ed25519KeyIdentity.generate();
    handleSignIn(FakeTransport.last(), {
      result: encodeDelegationChainResponse(
        await DelegationChain.create(
          Ed25519KeyIdentity.generate(),
          other.getPublicKey(),
          new Date(Date.now() + 3.6e6),
          { targets: [II_CANISTER] },
        ),
      ),
    });

    await expect(client.signIn()).rejects.toThrow(/does not delegate to the key/);
  });

  it('replaces the app credential rather than clearing it while signing in', async () => {
    const storage = spyStorage();
    const client = new AuthClient({
      credentialStorage: storage,
      idleOptions: { disableIdle: true },
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    const first = await storage.get(SLOTS.app);

    handleSignIn(FakeTransport.last());
    await client.signIn();

    // The slot every tab of this origin reads is never emptied: a ceremony mints
    // into its own slot and the promotion overwrites, so a sign-in that failed
    // would have cost the other tabs nothing.
    expect(storage.remove).not.toHaveBeenCalledWith(SLOTS.app);
    expect((await storage.get(SLOTS.app))?.chain?.toJSON()).not.toEqual(first?.chain?.toJSON());
    // And the ceremony's own slot does not outlive it.
    expect(await storage.get(SLOTS.appPending)).toBeNull();
  });

  it('leaves the shared app credential alone when a ceremony fails', async () => {
    const storage = spyStorage();
    const client = new AuthClient({
      credentialStorage: storage,
      idleOptions: { disableIdle: true },
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    const before = await storage.get(SLOTS.app);

    // A ceremony that never resolves: nothing shared may change on its account.
    minted.refuse = true;
    await expect(client.signIn()).rejects.toThrow();
    minted.refuse = false;

    expect((await storage.get(SLOTS.app))?.chain?.toJSON()).toEqual(before?.chain?.toJSON());
  });

  it('ends the session at the canister when signing out', async () => {
    const client = new AuthClient({ idleOptions: { disableIdle: true } });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    const before = minted.revoked;

    await client.signOut();

    expect(minted.revoked).toBe(before + 1);
  });

  it('carries the configured canister and agent options to the minter', async () => {
    const canisterId = Principal.fromText('aaaaa-aa');
    const agentOptions = { host: 'https://example.test' };
    const client = new AuthClient({
      identityProvider: { canisterId },
      agentOptions,
      idleOptions: { disableIdle: true },
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    expect(minted.createdWith.at(-1)).toEqual({ canisterId, agentOptions });
  });

  it('clears both credentials on sign-out, not just the session', async () => {
    const credentialStorage = new MemoryCredentialStorage();
    const client = new AuthClient({ credentialStorage, idleOptions: { disableIdle: true } });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    expect(await credentialStorage.get(SLOTS.app)).not.toBeNull();

    await client.signOut();

    // Teardown covers every slot rather than whichever one a caller names, so a
    // delegation cannot outlive the sign-in it was minted under.
    expect(await credentialStorage.get(SLOTS.session)).toBeNull();
    expect(await credentialStorage.get(SLOTS.app)).toBeNull();
  });

  it('clears the state storage on sign-out', async () => {
    const stateStorage = new MemoryStateStorage();
    const client = new AuthClient({ stateStorage, idleOptions: { disableIdle: true } });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    expect(stateStorage.get()).not.toBeNull();

    await client.signOut();

    expect(stateStorage.get()).toBeNull();
  });
});

describe('AuthClient idle behavior', () => {
  it('should sign out after idle and reload the window by default', async () => {
    const storage = spyStorage();
    const client = new AuthClient({
      credentialStorage: storage,
      idleOptions: { idleTimeout: 1000 },
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    expect(storage.remove).not.toHaveBeenCalledWith(SLOTS.session);

    await new Promise((r) => setTimeout(r, 1100));

    expect(storage.remove).toHaveBeenCalledWith(SLOTS.session);
    expect(window.location.reload).toHaveBeenCalled();
    expect(client.isAuthenticated()).toBe(false);
  });

  it('does not reload when idle sign-out fails (would otherwise restore the session)', async () => {
    const storage = spyStorage();
    const remove = storage.remove;
    // Only the session's removal fails: sign-in clears the app slot first, and a
    // sign-in that could not start would not reach the idle timer at all.
    storage.remove = vi.fn(async (slot: string) => {
      if (slot === SLOTS.session) throw new Error('storage unavailable');
      return remove(slot);
    });
    const client = new AuthClient({
      credentialStorage: storage,
      idleOptions: { idleTimeout: 1000 },
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    await new Promise((r) => setTimeout(r, 1100));

    // Teardown was attempted but failed; reloading now would `#hydrate` the
    // still-valid session, so the callback must swallow the error and not reload.
    expect(storage.remove).toHaveBeenCalled();
    expect(window.location.reload).not.toHaveBeenCalled();
  });

  it('should not reload the page if the default callback is disabled', async () => {
    const storage = spyStorage();
    const client = new AuthClient({
      credentialStorage: storage,
      idleOptions: { idleTimeout: 1000, disableDefaultIdleCallback: true },
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    await new Promise((r) => setTimeout(r, 1100));

    expect(storage.remove).not.toHaveBeenCalledWith(SLOTS.session);
    expect(window.location.reload).not.toHaveBeenCalled();
  });

  it('should call onIdle instead of the default behavior when provided', async () => {
    const idleCb = vi.fn();
    const client = new AuthClient({
      idleOptions: { idleTimeout: 1000, onIdle: idleCb },
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    // Wait for the idle timeout to fire (real timers).
    await new Promise((r) => setTimeout(r, 1100));

    expect(window.location.reload).not.toHaveBeenCalled();
    expect(idleCb).toHaveBeenCalled();
  });
});

describe('IdbCredentialStorage', () => {
  it('should handle get and set', async () => {
    const storage = new IdbCredentialStorage();
    const identity = await storage.create();
    const chain = await createTestDelegation(Ed25519KeyIdentity.generate());
    await storage.set(SLOTS.session, { identity, chain });

    const stored = await storage.get(SLOTS.session);
    expect(stored?.identity.getPublicKey().toDer()).toEqual(identity.getPublicKey().toDer());
    expect(stored?.chain?.toJSON()).toEqual(chain.toJSON());
  });
});

describe('Session restoration', () => {
  const testSecrets = [
    '302a300506032b6570032100d1fa89134802051c8b5d4e53c08b87381b87097bca4c4f348611eb8ce6c91809',
    '4bbff6b476463558d7be318aa342d1a97778d70833038680187950e9e02486c0d1fa89134802051c8b5d4e53c08b87381b87097bca4c4f348611eb8ce6c91809',
  ];

  it('should restore an existing Ed25519Key and delegation', async () => {
    vi.setSystemTime(new Date('2020-01-01T00:00:00.000Z'));

    const expiration = new Date('2020-01-03T00:00:00.000Z');
    const key = Ed25519KeyIdentity.fromJSON(JSON.stringify(testSecrets));
    const chain = await createTestDelegation(key, expiration);

    const client = new AuthClient({
      credentialStorage: spyStorage({ identity: key, chain }),
      stateStorage: stateFor(chain),
    });
    const identity = await client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(false);
  });

  it('should remain anonymous with a key but no delegation', async () => {
    vi.setSystemTime(new Date('2020-01-01T00:00:00.000Z'));

    const key = Ed25519KeyIdentity.fromJSON(JSON.stringify(testSecrets));
    // A record with no chain is only legal in a ceremony's own slot, so one
    // found under the session slot is not a session, and is cleared.
    const storage = spyStorage({ identity: key });
    const client = new AuthClient({ credentialStorage: storage });

    const identity = await client.getIdentity();

    expect(identity.getPrincipal().isAnonymous()).toBe(true);
    expect(storage.remove).toHaveBeenCalledWith(SLOTS.session);
    expect(await storage.get(SLOTS.session)).toBeNull();
  });

  it('should clear storage when the delegation has expired', async () => {
    vi.setSystemTime(new Date('2020-01-01T00:00:00.000Z'));

    const expiration = new Date('2019-12-30T00:00:00.000Z');
    const key = Ed25519KeyIdentity.fromJSON(JSON.stringify(testSecrets));
    const chain = await createTestDelegation(key, expiration);

    const storage = spyStorage({ identity: key, chain });

    const client = new AuthClient({ credentialStorage: storage });
    const identity = await client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(true);
    expect(storage.remove).toHaveBeenCalled();
  });
});

describe('AuthClient requestAttributes', () => {
  it('should send a JSON-RPC request and return decoded data and signature', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleRequestAttributes(transport);

    const nonce = new Uint8Array(32).fill(1);
    const result = await client.requestAttributes({
      keys: ['email', 'name'],
      nonce: () => Promise.resolve(nonce),
    });

    const sent = transport.requests[0];
    expect(sent.method).toBe('ii-icrc3-attributes');
    expect(sent.params?.keys).toEqual(['email', 'name']);
    expect(sent.params?.nonce).toBe(btoa(String.fromCharCode(...nonce)));
    expect(Array.from(result.data)).toEqual(Array.from(new TextEncoder().encode('hello')));
    expect(Array.from(result.signature)).toEqual(Array.from(new TextEncoder().encode('sig')));
  });

  it('should use a provided nonce', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleRequestAttributes(transport);

    const nonce = new Uint8Array(32).fill(42);
    await client.requestAttributes({ keys: ['email'], nonce: () => Promise.resolve(nonce) });

    expect(transport.requests[0].params?.nonce).toBe(btoa(String.fromCharCode(...nonce)));
  });

  it('should forward different nonces as distinct base64 values', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleRequestAttributes(transport);

    await client.requestAttributes({
      keys: ['email'],
      nonce: () => Promise.resolve(new Uint8Array(32).fill(1)),
    });
    await client.requestAttributes({
      keys: ['email'],
      nonce: () => Promise.resolve(new Uint8Array(32).fill(2)),
    });

    expect(transport.requests[0].params?.nonce).not.toBe(transport.requests[1].params?.nonce);
  });

  it('should throw when the response contains an error', async () => {
    const client = new AuthClient();
    handleRequestAttributes(FakeTransport.last(), {
      error: { code: -1, message: 'not supported' },
    });

    const nonce = new Uint8Array(32).fill(1);
    await expect(
      client.requestAttributes({ keys: ['email'], nonce: () => Promise.resolve(nonce) }),
    ).rejects.toThrow('not supported');
  });

  it('should throw when the response is missing data or signature', async () => {
    const client = new AuthClient();
    handleRequestAttributes(FakeTransport.last(), { result: { data: btoa('hello') } });

    const nonce = new Uint8Array(32).fill(1);
    await expect(
      client.requestAttributes({ keys: ['email'], nonce: () => Promise.resolve(nonce) }),
    ).rejects.toThrow('Invalid response: missing data or signature');
  });

  it('should accept a nonce callback returning a promise and forward the resolved value', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleRequestAttributes(transport);

    const nonceBytes = new Uint8Array(32).fill(7);
    const result = await client.requestAttributes({
      keys: ['email'],
      nonce: () => Promise.resolve(nonceBytes),
    });

    expect(transport.requests[0].params?.nonce).toBe(btoa(String.fromCharCode(...nonceBytes)));
    expect(Array.from(result.data)).toEqual(Array.from(new TextEncoder().encode('hello')));
  });

  it('should open the transport channel before awaiting a nonce promise', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleRequestAttributes(transport);

    const establishOrder: string[] = [];
    const originalEstablish = transport.establishChannel.bind(transport);
    transport.establishChannel = async () => {
      establishOrder.push('establish');
      return originalEstablish();
    };

    const nonceBytes = new Uint8Array(32).fill(9);
    const noncePromise = new Promise<Uint8Array>((resolve) => {
      // Resolving in a later microtask so the channel has time to open first.
      queueMicrotask(() => {
        establishOrder.push('resolve-nonce');
        resolve(nonceBytes);
      });
    });

    await client.requestAttributes({ keys: ['email'], nonce: () => noncePromise });

    expect(establishOrder).toEqual(['establish', 'resolve-nonce']);
    expect(transport.requests[0].params?.nonce).toBe(btoa(String.fromCharCode(...nonceBytes)));
  });

  it('should propagate rejection from a nonce promise', async () => {
    const client = new AuthClient();
    handleRequestAttributes(FakeTransport.last());

    await expect(
      client.requestAttributes({ keys: ['email'], nonce: () => Promise.reject(new Error('boom')) }),
    ).rejects.toThrow('boom');
  });
});

describe('AuthClient signIn + requestAttributes', () => {
  it('should resolve both when issued in parallel', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleSignIn(transport);
    handleRequestAttributes(transport);

    const [identity, attributes] = await Promise.all([
      client.signIn(),
      client.requestAttributes({
        keys: ['email'],
        nonce: () => Promise.resolve(new Uint8Array(32).fill(1)),
      }),
    ]);

    expect(identity.getPrincipal().isAnonymous()).toBe(false);
    expect(Array.from(attributes.data)).toEqual(Array.from(new TextEncoder().encode('hello')));
  });

  it('should resolve requestAttributes after a completed signIn', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleSignIn(transport);
    handleRequestAttributes(transport);

    const identity = await client.signIn();
    const attributes = await client.requestAttributes({
      keys: ['email'],
      nonce: () => Promise.resolve(new Uint8Array(32).fill(1)),
    });

    expect(identity.getPrincipal().isAnonymous()).toBe(false);
    expect(Array.from(attributes.data)).toEqual(Array.from(new TextEncoder().encode('hello')));
  });

  it('should resolve signIn after a completed requestAttributes', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleSignIn(transport);
    handleRequestAttributes(transport);

    const attributes = await client.requestAttributes({
      keys: ['email'],
      nonce: () => Promise.resolve(new Uint8Array(32).fill(1)),
    });
    const identity = await client.signIn();

    expect(Array.from(attributes.data)).toEqual(Array.from(new TextEncoder().encode('hello')));
    expect(identity.getPrincipal().isAnonymous()).toBe(false);
  });
});
