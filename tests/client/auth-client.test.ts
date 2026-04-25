import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthClient } from '../../src/client/auth-client.ts';
import { IdleManager } from '../../src/client/idle-manager.ts';
import {
  type AuthClientStorage,
  IdbStorage,
  KEY_STORAGE_DELEGATION,
  KEY_STORAGE_KEY,
  LocalStorage,
} from '../../src/client/storage.ts';
import { FakeTransport } from './fake-transport.ts';

// Swap `PostMessageTransport` for `FakeTransport` so `AuthClient` uses the real
// `Signer` over an in-memory transport — no window is opened and nothing about
// the signer's JSON-RPC correlation is faked.
vi.mock('@icp-sdk/signer/web', async () => {
  const { FakeTransport } = await import('./fake-transport.ts');
  return { PostMessageTransport: FakeTransport };
});

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
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

// Shared default bodies — declared as constants so both helpers use a
// parameter-default form consistently. `DelegationChain.create` is async, so
// top-level `await` is used; `await` isn't allowed inside param defaults.
const DEFAULT_SIGN_IN_BODY: JsonRpcBody = {
  result: encodeDelegationChainResponse(await createTestDelegation(Ed25519KeyIdentity.generate())),
};

const DEFAULT_REQUEST_ATTRIBUTES_BODY: JsonRpcBody = {
  result: { data: btoa('hello'), signature: btoa('sig') },
};

/**
 * Registers an `icrc34_delegation` handler that returns the given body.
 * Defaults to a valid delegation chain so `signIn()` resolves successfully.
 */
function handleSignIn(transport: FakeTransport, body: JsonRpcBody = DEFAULT_SIGN_IN_BODY): void {
  transport.onRequest((req) => {
    if (req.method !== 'icrc34_delegation') return;
    if (req.id === undefined || req.id === null) return;
    return { jsonrpc: '2.0', id: req.id, ...body };
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
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(async (x) => {
        if (x === KEY_STORAGE_DELEGATION) return JSON.stringify(chain.toJSON());
        return null;
      }),
      set: vi.fn(),
    };
    const client = new AuthClient({ identity, storage });
    const resolved = await client.getIdentity();
    expect(resolved.getPrincipal().isAnonymous()).toBe(false);
  });

  it('should log users out', async () => {
    const client = new AuthClient();
    await client.logout();
    expect(client.isAuthenticated()).toBe(false);
    const identity = await client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(true);
  });

  it('should not initialize an idleManager if the user is not logged in', async () => {
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

  it('should forward targets and maxTimeToLive to the delegation request', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleSignIn(transport);

    const target = Principal.fromText('aaaaa-aa');
    await client.signIn({ targets: [target], maxTimeToLive: 1_000_000n });

    const req = transport.requests[0];
    expect(req.method).toBe('icrc34_delegation');
    expect(req.params?.targets).toEqual([target.toText()]);
    expect(req.params?.maxTimeToLive).toBe('1000000');
  });

  it('should forward derivationOrigin on every request as icrc95DerivationOrigin', async () => {
    const client = new AuthClient({ derivationOrigin: 'https://example.com' });
    const transport = FakeTransport.last();
    handleSignIn(transport);

    await client.signIn();

    expect(transport.requests[0].params?.icrc95DerivationOrigin).toBe('https://example.com');
  });

  it('should persist delegation and key after sign-in', async () => {
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn(),
    };
    const client = new AuthClient({ storage });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    expect(storage.set).toHaveBeenCalledWith(KEY_STORAGE_DELEGATION, expect.any(String));
    expect(storage.set).toHaveBeenCalledWith(KEY_STORAGE_KEY, expect.anything());
  });

  it('should generate a fresh key for each sign-in', async () => {
    const storedKeys: unknown[] = [];
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn(async (k, v) => {
        if (k === KEY_STORAGE_KEY) storedKeys.push(v);
      }),
    };
    const client = new AuthClient({ storage, keyType: 'Ed25519' });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    await client.signIn();

    expect(storedKeys).toHaveLength(2);
    expect(storedKeys[0]).not.toEqual(storedKeys[1]);
  });

  it('should set the localStorage expiration flag after sign-in', async () => {
    const client = new AuthClient({ idleOptions: { disableIdle: true } });
    handleSignIn(FakeTransport.last());
    expect(client.isAuthenticated()).toBe(false);
    await client.signIn();
    expect(client.isAuthenticated()).toBe(true);
  });

  it('should clear the localStorage expiration flag on logout', async () => {
    const client = new AuthClient({ idleOptions: { disableIdle: true } });
    handleSignIn(FakeTransport.last());
    await client.signIn();
    expect(client.isAuthenticated()).toBe(true);
    await client.logout();
    expect(client.isAuthenticated()).toBe(false);
  });
});

describe('AuthClient idle behavior', () => {
  it('should log out after idle and reload the window by default', async () => {
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn(),
    };
    const client = new AuthClient({
      storage,
      idleOptions: { idleTimeout: 1000 },
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    expect(storage.remove).not.toHaveBeenCalled();

    await new Promise((r) => setTimeout(r, 1100));

    expect(storage.remove).toHaveBeenCalled();
    expect(window.location.reload).toHaveBeenCalled();
    expect(client.isAuthenticated()).toBe(false);
  });

  it('should not reload the page if the default callback is disabled', async () => {
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn(),
    };
    const client = new AuthClient({
      storage,
      idleOptions: { idleTimeout: 1000, disableDefaultIdleCallback: true },
    });
    handleSignIn(FakeTransport.last());
    await client.signIn();

    await new Promise((r) => setTimeout(r, 1100));

    expect(storage.remove).not.toHaveBeenCalled();
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

describe('IdbStorage', () => {
  it('should handle get and set', async () => {
    const storage = new IdbStorage();
    await storage.set('testKey', 'testValue');
    expect(await storage.get('testKey')).toBe('testValue');
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

    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(async (x) => {
        if (x === KEY_STORAGE_DELEGATION) return JSON.stringify(chain.toJSON());
        if (x === KEY_STORAGE_KEY) return JSON.stringify(testSecrets);
        return null;
      }),
      set: vi.fn(),
    };

    const client = new AuthClient({ storage });
    const identity = await client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(false);
  });

  it('should remain anonymous with a key but no delegation', async () => {
    vi.setSystemTime(new Date('2020-01-01T00:00:00.000Z'));

    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(async (x) => {
        if (x === KEY_STORAGE_KEY) return JSON.stringify(testSecrets);
        return null;
      }),
      set: vi.fn(),
    };

    const client = new AuthClient({ storage });
    const identity = await client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(true);
  });

  it('should clear storage when the delegation has expired', async () => {
    vi.setSystemTime(new Date('2020-01-01T00:00:00.000Z'));

    const expiration = new Date('2019-12-30T00:00:00.000Z');
    const key = Ed25519KeyIdentity.fromJSON(JSON.stringify(testSecrets));
    const chain = await createTestDelegation(key, expiration);

    const fakeStore: Record<string, string> = {};
    fakeStore[KEY_STORAGE_DELEGATION] = JSON.stringify(chain.toJSON());
    fakeStore[KEY_STORAGE_KEY] = JSON.stringify(testSecrets);

    const storage: AuthClientStorage = {
      remove: vi.fn(async (x) => {
        delete fakeStore[x];
      }),
      get: vi.fn(async (x) => fakeStore[x] ?? null),
      set: vi.fn(),
    };

    const client = new AuthClient({ storage });
    const identity = await client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(true);
    expect(storage.remove).toHaveBeenCalled();
  });
});

describe('Migration from localStorage', () => {
  it('should proceed normally if no values are stored in localStorage', async () => {
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn(),
    };

    new AuthClient({ storage });
    await new Promise((r) => setTimeout(r, 0)); // wait for hydration

    // No migration should have occurred (no set calls for delegation/key)
    expect(storage.set).not.toHaveBeenCalled();
  });

  it('should migrate storage from localStorage', async () => {
    const legacyStorage = new LocalStorage();
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn(),
    };

    await legacyStorage.set(KEY_STORAGE_DELEGATION, 'test');
    await legacyStorage.set(KEY_STORAGE_KEY, 'key');

    new AuthClient({ storage });
    await new Promise((r) => setTimeout(r, 0)); // wait for hydration

    expect(storage.set).toHaveBeenCalledWith(KEY_STORAGE_DELEGATION, 'test');
    expect(storage.set).toHaveBeenCalledWith(KEY_STORAGE_KEY, 'key');
  });
});

describe('AuthClient requestAttributes', () => {
  it('should send a JSON-RPC request and return decoded data and signature', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleRequestAttributes(transport);

    const nonce = new Uint8Array(32).fill(1);
    const result = await client.requestAttributes({ keys: ['email', 'name'], nonce });

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
    await client.requestAttributes({ keys: ['email'], nonce });

    expect(transport.requests[0].params?.nonce).toBe(btoa(String.fromCharCode(...nonce)));
  });

  it('should forward different nonces as distinct base64 values', async () => {
    const client = new AuthClient();
    const transport = FakeTransport.last();
    handleRequestAttributes(transport);

    await client.requestAttributes({ keys: ['email'], nonce: new Uint8Array(32).fill(1) });
    await client.requestAttributes({ keys: ['email'], nonce: new Uint8Array(32).fill(2) });

    expect(transport.requests[0].params?.nonce).not.toBe(transport.requests[1].params?.nonce);
  });

  it('should throw when the response contains an error', async () => {
    const client = new AuthClient();
    handleRequestAttributes(FakeTransport.last(), {
      error: { code: -1, message: 'not supported' },
    });

    const nonce = new Uint8Array(32).fill(1);
    await expect(client.requestAttributes({ keys: ['email'], nonce })).rejects.toThrow(
      'not supported',
    );
  });

  it('should throw when the response is missing data or signature', async () => {
    const client = new AuthClient();
    handleRequestAttributes(FakeTransport.last(), { result: { data: btoa('hello') } });

    const nonce = new Uint8Array(32).fill(1);
    await expect(client.requestAttributes({ keys: ['email'], nonce })).rejects.toThrow(
      'Invalid response: missing data or signature',
    );
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
      client.requestAttributes({ keys: ['email'], nonce: new Uint8Array(32).fill(1) }),
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
      nonce: new Uint8Array(32).fill(1),
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
      nonce: new Uint8Array(32).fill(1),
    });
    const identity = await client.signIn();

    expect(Array.from(attributes.data)).toEqual(Array.from(new TextEncoder().encode('hello')));
    expect(identity.getPrincipal().isAnonymous()).toBe(false);
  });
});
