import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
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

// Mock @icp-sdk/signer so login() doesn't open real windows.
const { mockSignerInstance, mockPostMessageTransport } = vi.hoisted(() => ({
  mockSignerInstance: {
    openChannel: vi.fn(),
    closeChannel: vi.fn(),
    requestDelegation: vi.fn(),
  },
  mockPostMessageTransport: vi.fn(),
}));

vi.mock('@icp-sdk/signer', () => ({
  Signer: class {
    openChannel = mockSignerInstance.openChannel;
    closeChannel = mockSignerInstance.closeChannel;
    requestDelegation = mockSignerInstance.requestDelegation;
  },
}));

vi.mock('@icp-sdk/signer/web', () => ({
  PostMessageTransport: mockPostMessageTransport,
}));

/**
 * Helper: creates a valid DelegationChain for testing.
 */
async function createTestDelegation(key: Ed25519KeyIdentity, expiration?: Date) {
  const exp = expiration ?? new Date(Date.now() + 24 * 60 * 60 * 1000); // 1 day from now
  return DelegationChain.create(key, key.getPublicKey(), exp);
}

/**
 * Helper: configures the mocked Signer so requestDelegation resolves with a test chain.
 */
async function mockSignerForLogin() {
  const key = Ed25519KeyIdentity.generate();
  const chain = await createTestDelegation(key);
  mockSignerInstance.openChannel.mockResolvedValue(undefined);
  mockSignerInstance.closeChannel.mockResolvedValue(undefined);
  mockSignerInstance.requestDelegation.mockResolvedValue(chain);
  return { key, chain };
}

beforeEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  localStorage.clear();
  mockSignerInstance.openChannel.mockReset();
  mockSignerInstance.closeChannel.mockReset();
  mockSignerInstance.requestDelegation.mockReset();
});

afterEach(async () => {
  // Reset the IdleManager singleton between tests.
  // Wait a tick to let any async callbacks (like logout) settle.
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
    mockPostMessageTransport.mockClear();
    new AuthClient({ openIdProvider: provider });
    const url = new URL(mockPostMessageTransport.mock.calls[0][0].url);
    expect(url.searchParams.get('openid')).toBe(expectedUrl);
  });

  it('should not include openid search param when openIdProvider is not set', () => {
    mockPostMessageTransport.mockClear();
    new AuthClient();
    const url = new URL(mockPostMessageTransport.mock.calls[0][0].url);
    expect(url.searchParams.has('openid')).toBe(false);
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

describe('AuthClient login', () => {
  it('should call onSuccess after a successful login', async () => {
    await mockSignerForLogin();
    const client = new AuthClient();
    const onSuccess = vi.fn();
    await client.login({ onSuccess });
    expect(onSuccess).toHaveBeenCalled();
  });

  it('should set up an idle manager after login', async () => {
    await mockSignerForLogin();
    const client = new AuthClient();
    await client.login();
    expect(client.idleManager).toBeDefined();
  });

  it('should not set up an idle manager if disableIdle is set', async () => {
    await mockSignerForLogin();
    const client = new AuthClient({ idleOptions: { disableIdle: true } });
    await client.login();
    expect(client.idleManager).toBeUndefined();
  });

  it('should throw on failure when no onError is provided', async () => {
    mockSignerInstance.openChannel.mockRejectedValue(new Error('connection failed'));

    const client = new AuthClient();
    await expect(client.login()).rejects.toThrow('connection failed');
  });

  it('should call onError instead of throwing when onError is provided', async () => {
    mockSignerInstance.openChannel.mockRejectedValue(new Error('connection failed'));

    const client = new AuthClient();
    const onError = vi.fn();
    await client.login({ onError });
    expect(onError).toHaveBeenCalledWith('connection failed');
  });

  it('should persist delegation and key after login', async () => {
    await mockSignerForLogin();
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn(),
    };
    const client = new AuthClient({ storage });
    await client.login();

    expect(storage.set).toHaveBeenCalledWith(KEY_STORAGE_DELEGATION, expect.any(String));
    expect(storage.set).toHaveBeenCalledWith(KEY_STORAGE_KEY, expect.anything());
  });

  it('should generate a fresh key for each login', async () => {
    await mockSignerForLogin();
    const storedKeys: unknown[] = [];
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn(async (k, v) => {
        if (k === KEY_STORAGE_KEY) storedKeys.push(v);
      }),
    };
    const client = new AuthClient({ storage, keyType: 'Ed25519' });
    await client.login();
    await client.login();

    expect(storedKeys).toHaveLength(2);
    expect(storedKeys[0]).not.toEqual(storedKeys[1]);
  });

  it('should set the localStorage expiration flag after login', async () => {
    await mockSignerForLogin();
    const client = new AuthClient();
    expect(client.isAuthenticated()).toBe(false);
    await client.login();
    expect(client.isAuthenticated()).toBe(true);
  });

  it('should clear the localStorage expiration flag on logout', async () => {
    await mockSignerForLogin();
    const client = new AuthClient();
    await client.login();
    expect(client.isAuthenticated()).toBe(true);
    await client.logout();
    expect(client.isAuthenticated()).toBe(false);
  });
});

describe('AuthClient idle behavior', () => {
  it('should log out after idle and reload the window by default', async () => {
    vi.stubGlobal('location', { reload: vi.fn() });

    await mockSignerForLogin();
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn(),
    };
    const client = new AuthClient({
      storage,
      idleOptions: { idleTimeout: 1000 },
    });
    await client.login();

    expect(storage.remove).not.toHaveBeenCalled();

    await new Promise((r) => setTimeout(r, 1100));

    expect(storage.remove).toHaveBeenCalled();
    expect(window.location.reload).toHaveBeenCalled();
  });

  it('should not reload the page if the default callback is disabled', async () => {
    vi.stubGlobal('location', { reload: vi.fn() });

    await mockSignerForLogin();
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn(),
    };
    const client = new AuthClient({
      storage,
      idleOptions: { idleTimeout: 1000, disableDefaultIdleCallback: true },
    });
    await client.login();

    await new Promise((r) => setTimeout(r, 1100));

    expect(storage.remove).not.toHaveBeenCalled();
    expect(window.location.reload).not.toHaveBeenCalled();
  });

  it('should call onIdle instead of the default behavior when provided', async () => {
    vi.stubGlobal('location', { reload: vi.fn() });

    await mockSignerForLogin();
    const idleCb = vi.fn();
    const client = new AuthClient({
      idleOptions: { idleTimeout: 1000, onIdle: idleCb },
    });
    await client.login();

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
    // Wait for hydration
    await new Promise((r) => setTimeout(r, 0));

    // No migration should have occurred (no set calls for delegation/key)
    expect(storage.set).not.toHaveBeenCalled();
  });

  it('should migrate storage from localStorage', async () => {
    const ls = new LocalStorage();
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn(),
    };

    await ls.set(KEY_STORAGE_DELEGATION, 'test');
    await ls.set(KEY_STORAGE_KEY, 'key');

    new AuthClient({ storage });
    // Wait for hydration
    await new Promise((r) => setTimeout(r, 0));

    expect(storage.set).toHaveBeenCalledWith(KEY_STORAGE_DELEGATION, 'test');
    expect(storage.set).toHaveBeenCalledWith(KEY_STORAGE_KEY, 'key');
  });
});
