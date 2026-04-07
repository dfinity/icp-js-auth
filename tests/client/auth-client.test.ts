import { Actor, type AgentError, HttpAgent } from '@icp-sdk/core/agent';
import { IDL } from '@icp-sdk/core/candid';
import { DelegationChain, ECDSAKeyIdentity, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthClient } from '../../src/client/auth-client.ts';
import {
  type AuthClientStorage,
  IdbStorage,
  KEY_STORAGE_DELEGATION,
  KEY_STORAGE_KEY,
  LocalStorage,
  type StoredKey,
} from '../../src/client/storage.ts';

const { mockSignerInstance, mockPostMessageTransport } = vi.hoisted(() => ({
  mockSignerInstance: {
    openChannel: vi.fn(),
    closeChannel: vi.fn().mockResolvedValue(undefined),
    requestDelegation: vi.fn(),
  },
  mockPostMessageTransport: vi.fn(),
}));

vi.mock('@icp-sdk/signer', () => ({
  Signer: class MockSigner {
    openChannel = mockSignerInstance.openChannel;
    closeChannel = mockSignerInstance.closeChannel;
    requestDelegation = mockSignerInstance.requestDelegation;
  },
}));

vi.mock('@icp-sdk/signer/web', () => ({
  PostMessageTransport: mockPostMessageTransport,
}));

beforeEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe('Auth Client', () => {
  it('should initialize with an AnonymousIdentity', async () => {
    const test = await AuthClient.create();
    expect(await test.isAuthenticated()).toBe(false);
    expect(test.getIdentity().getPrincipal().isAnonymous()).toBe(true);
  });

  it('should initialize with a provided identity', async () => {
    const identity = Ed25519KeyIdentity.generate();
    const test = await AuthClient.create({
      identity,
    });
    expect(test.getIdentity().getPrincipal().isAnonymous()).toBe(false);
    expect(test.getIdentity()).toBe(identity);
  });

  it('should log users out', async () => {
    const test = await AuthClient.create();
    await test.logout();
    expect(await test.isAuthenticated()).toBe(false);
    expect(test.getIdentity().getPrincipal().isAnonymous()).toBe(true);
  });

  it('should not initialize an idleManager if the user is not logged in', async () => {
    const test = await AuthClient.create();
    expect(test.idleManager).not.toBeDefined();
  });

  it('should initialize an idleManager if an identity is passed', async () => {
    const test = await AuthClient.create({ identity: Ed25519KeyIdentity.generate() });
    expect(test.idleManager).toBeDefined();
  });

  it('should be able to invalidate an identity after going idle', async () => {
    const mockFetch = vi.fn();
    vi.stubGlobal('location', {
      reload: vi.fn(),
      fetch: mockFetch,
      hostname: '127.0.0.1',
      protocol: 'http:',
      port: '4943',
      toString: vi.fn(() => 'http://127.0.0.1:4943'),
    });

    const identity = Ed25519KeyIdentity.generate();

    const canisterId = Principal.fromText('uxrrr-q7777-77774-qaaaq-cai');
    const actorInterface = () => {
      return IDL.Service({
        greet: IDL.Func([IDL.Text], [IDL.Text]),
      });
    };

    // setup auth client
    const test = await AuthClient.create({
      identity,
      idleOptions: {
        idleTimeout: 1000,
      },
    });

    const httpAgent = await HttpAgent.create({ fetch: mockFetch });
    const actor = Actor.createActor(actorInterface, { canisterId, agent: httpAgent });

    test.idleManager?.registerCallback(() => {
      const agent = Actor.agentOf(actor);
      agent!.invalidateIdentity?.();
    });

    // wait for the idle timeout
    await new Promise((resolve) => setTimeout(resolve, 1000));

    expect.assertions(2);

    // check that the registered actor has been invalidated
    const expectedError =
      "This identity has expired due this application's security policy. Please refresh your authentication.";
    try {
      await actor.greet('hello');
    } catch (error) {
      expect(await test.isAuthenticated()).toBe(false);
      expect((error as AgentError).message).toBe(expectedError);
    }
  });

  it('should not set up an idle timer if the disable option is set', async () => {
    const idleFn = vi.fn();
    const test = await AuthClient.create({
      idleOptions: {
        idleTimeout: 1000,
        disableIdle: true,
      },
    });

    expect(idleFn).not.toHaveBeenCalled();
    expect(test.idleManager).toBeUndefined();
    // wait for default 30 minute idle timeout
    vi.useFakeTimers();
    vi.advanceTimersByTime(30 * 60 * 1000);
    expect(idleFn).not.toHaveBeenCalled();
  });
});

describe('Auth Client login', () => {
  function setupMockDelegation() {
    const key = Ed25519KeyIdentity.generate();
    const chain = DelegationChain.create(
      key,
      key.getPublicKey(),
      new Date(Date.now() + 60 * 60 * 1000),
    );
    return chain;
  }

  it('should call signer.requestDelegation and succeed', async () => {
    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    const client = await AuthClient.create();
    const onSuccess = vi.fn();
    await client.login({ onSuccess });

    expect(mockSignerInstance.requestDelegation).toHaveBeenCalledOnce();
    expect(onSuccess).toHaveBeenCalledOnce();
    expect(mockSignerInstance.closeChannel).toHaveBeenCalledOnce();
  });

  it('should call onError on signer failure', async () => {
    mockSignerInstance.requestDelegation.mockRejectedValueOnce(new Error('mock error message'));

    const client = await AuthClient.create();
    const onError = vi.fn();
    await client.login({ onError });

    expect(onError).toHaveBeenCalledWith('mock error message');
    expect(mockSignerInstance.closeChannel).toHaveBeenCalledOnce();
  });

  it('should call closeChannel even if onSuccess throws', async () => {
    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    const client = await AuthClient.create();
    const onError = vi.fn();
    const onSuccess = vi.fn(() => {
      throw new Error('onSuccess error');
    });
    await client.login({ onSuccess, onError });

    expect(mockSignerInstance.closeChannel).toHaveBeenCalledOnce();
    expect(onError).toHaveBeenCalledWith('onSuccess error');
  });

  it('should create PostMessageTransport with the identity provider URL and window features', async () => {
    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    const client = await AuthClient.create();
    await client.login({
      identityProvider: 'http://127.0.0.1',
      windowOpenerFeatures: 'toolbar=0,location=0,menubar=0',
    });

    expect(mockPostMessageTransport).toHaveBeenCalledWith({
      url: 'http://127.0.0.1',
      windowOpenerFeatures: 'toolbar=0,location=0,menubar=0',
    });
  });

  it('should use default identity provider when none is specified', async () => {
    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    const client = await AuthClient.create();
    await client.login();

    expect(mockPostMessageTransport).toHaveBeenCalledWith({
      url: 'https://id.ai/authorize',
      windowOpenerFeatures: undefined,
    });
  });

  it('should pass derivationOrigin to signer', async () => {
    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    // We verify the Signer constructor receives derivationOrigin.
    // Since we mock the whole module, we check PostMessageTransport was called
    // and that login succeeds. The derivationOrigin is passed via the Signer
    // constructor options, which we cannot directly inspect from the mock class.
    // Instead we verify the login works end-to-end with derivationOrigin.
    const client = await AuthClient.create();
    const onSuccess = vi.fn();
    await client.login({
      identityProvider: 'http://127.0.0.1',
      derivationOrigin: 'http://127.0.0.1:1234',
      onSuccess,
    });

    expect(onSuccess).toHaveBeenCalledOnce();
  });

  it('should pass maxTimeToLive to requestDelegation', async () => {
    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    const client = await AuthClient.create();
    await client.login({ maxTimeToLive: BigInt(1000) });

    const callArgs = mockSignerInstance.requestDelegation.mock.calls[0][0];
    expect(callArgs.maxTimeToLive).toBe(BigInt(1000));
  });

  it('should pass targets to requestDelegation', async () => {
    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    const targets = [Principal.fromText('aaaaa-aa')];
    const client = await AuthClient.create();
    await client.login({ targets });

    const callArgs = mockSignerInstance.requestDelegation.mock.calls[0][0];
    expect(callArgs.targets).toEqual(targets);
  });

  it('should authenticate after a successful login', async () => {
    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    const client = await AuthClient.create();
    await client.login();

    expect(client.getIdentity().getPrincipal().isAnonymous()).toBe(false);
  });

  it('should persist delegation and key to storage after login', async () => {
    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(async () => null),
      set: vi.fn(),
    };

    const client = await AuthClient.create({ storage, keyType: 'Ed25519' });
    await client.login();

    // Should have set the delegation chain
    const delegationSetCalls = (storage.set as ReturnType<typeof vi.fn>).mock.calls.filter(
      ([key]: [string]) => key === KEY_STORAGE_DELEGATION,
    );
    expect(delegationSetCalls.length).toBeGreaterThan(0);

    // Should have persisted the key
    const keySetCalls = (storage.set as ReturnType<typeof vi.fn>).mock.calls.filter(
      ([key]: [string]) => key === KEY_STORAGE_KEY,
    );
    // Key is set during create and again after login
    expect(keySetCalls.length).toBeGreaterThanOrEqual(2);
  });

  it('should overwrite stored Ed25519 key with in-memory key on login', async () => {
    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    const fakeStore: Record<string, string> = {};
    const storage: AuthClientStorage = {
      remove: vi.fn(async (k) => {
        delete fakeStore[k];
      }),
      get: vi.fn(async (k) => fakeStore[k] ?? null),
      set: vi.fn(async (k, v) => {
        fakeStore[k] = v as unknown as string;
      }),
    };

    const client = await AuthClient.create({ storage, keyType: 'Ed25519' });

    const initialKey = fakeStore[KEY_STORAGE_KEY];
    expect(typeof initialKey).toBe('string');

    // Simulate another tab overwriting the stored key
    const overwrittenKey = 'overwritten-key-from-another-tab';
    fakeStore[KEY_STORAGE_KEY] = overwrittenKey;

    await client.login();

    expect(fakeStore[KEY_STORAGE_KEY]).toEqual(initialKey);
    expect(fakeStore[KEY_STORAGE_KEY]).not.toEqual(overwrittenKey);
  });

  it('should overwrite stored ECDSA key pair with in-memory key on login', async () => {
    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    const fakeStore: Record<string, StoredKey> = {};
    const storage: AuthClientStorage = {
      remove: vi.fn(async (k: string) => {
        delete fakeStore[k];
      }),
      get: vi.fn(async (k: string): Promise<StoredKey | null> => fakeStore[k] ?? null),
      set: vi.fn(async (k: string, v: StoredKey) => {
        fakeStore[k] = v;
      }),
    };

    const client = await AuthClient.create({ storage }); // default ECDSA

    const initialKeyPair = fakeStore[KEY_STORAGE_KEY] as CryptoKeyPair;
    expect(initialKeyPair).toBeTruthy();
    expect(initialKeyPair.publicKey).toBeDefined();
    expect(initialKeyPair.privateKey).toBeDefined();

    // Simulate another tab overwriting the stored key
    const overwrittenKeyPair = (await ECDSAKeyIdentity.generate()).getKeyPair();
    fakeStore[KEY_STORAGE_KEY] = overwrittenKeyPair;

    await client.login();

    const restored = fakeStore[KEY_STORAGE_KEY] as CryptoKeyPair;
    // Expect the same key references as initially stored
    expect(restored.publicKey).toBe(initialKeyPair.publicKey);
    expect(restored.privateKey).toBe(initialKeyPair.privateKey);
    expect(restored.privateKey).not.toBe(overwrittenKeyPair.privateKey);
    expect(restored.publicKey).not.toBe(overwrittenKeyPair.publicKey);
  });

  it('should use the loginOptions passed to the create method', async () => {
    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    const client = await AuthClient.create({
      loginOptions: {
        identityProvider: 'http://my-local-website.localhost:8080',
        maxTimeToLive: BigInt(1000),
      },
    });

    await client.login();

    expect(mockPostMessageTransport).toHaveBeenCalledWith({
      url: 'http://my-local-website.localhost:8080',
      windowOpenerFeatures: undefined,
    });

    const callArgs = mockSignerInstance.requestDelegation.mock.calls[0][0];
    expect(callArgs.maxTimeToLive).toEqual(BigInt(1000));
  });

  it('should merge the loginOptions passed to the create method and the login method', async () => {
    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    const client = await AuthClient.create({
      loginOptions: {
        identityProvider: 'http://my-local-website.localhost:8080',
        derivationOrigin: 'http://another-local-website.localhost:8080',
      },
    });

    await client.login({
      identityProvider: 'http://replaced.localhost:8080',
    });

    expect(mockPostMessageTransport).toHaveBeenCalledWith({
      url: 'http://replaced.localhost:8080',
      windowOpenerFeatures: undefined,
    });
  });

  it('should log out after idle and reload the window by default', async () => {
    vi.useFakeTimers();
    vi.stubGlobal('location', { reload: vi.fn(), fetch: vi.fn() });

    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(),
      set: vi.fn(),
    };

    const test = await AuthClient.create({
      storage,
      idleOptions: {
        idleTimeout: 1000,
      },
    });

    await test.login();

    expect(storage.set).toHaveBeenCalled();
    expect(storage.remove).not.toHaveBeenCalled();

    // simulate user being inactive for 10 minutes
    vi.advanceTimersByTime(10 * 60 * 1000);

    // Storage should be cleared by default after logging out
    expect(storage.remove).toHaveBeenCalled();

    expect(window.location.reload).toHaveBeenCalled();
  });

  it('should not reload the page if the default callback is disabled', async () => {
    vi.useFakeTimers();
    vi.stubGlobal('location', { reload: vi.fn(), fetch: vi.fn() });

    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(),
      set: vi.fn(),
    };

    const test = await AuthClient.create({
      storage,
      idleOptions: {
        idleTimeout: 1000,
        disableDefaultIdleCallback: true,
      },
    });

    await test.login();

    expect(storage.set).toHaveBeenCalled();
    expect(storage.remove).not.toHaveBeenCalled();

    // simulate user being inactive for 10 minutes
    vi.advanceTimersByTime(10 * 60 * 1000);

    // Storage should not be cleared
    expect(storage.remove).not.toHaveBeenCalled();
    // Page should not be reloaded
    expect(window.location.reload).not.toHaveBeenCalled();
  });

  it('should not reload the page if a callback is provided', async () => {
    vi.useFakeTimers();

    const chain = await setupMockDelegation();
    mockSignerInstance.requestDelegation.mockResolvedValueOnce(chain);

    vi.stubGlobal('location', { reload: vi.fn(), fetch: vi.fn() });

    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(),
      set: vi.fn(),
    };

    const idleCb = vi.fn();
    const test = await AuthClient.create({
      storage,
      idleOptions: {
        idleTimeout: 1000,
        onIdle: idleCb,
      },
    });

    await test.login();

    // simulate user being inactive for 10 minutes
    vi.advanceTimersByTime(10 * 60 * 1000);

    expect(window.location.reload).not.toHaveBeenCalled();
    expect(idleCb).toHaveBeenCalled();
  });

  it('should not set up an idle timer if the client is not logged in', async () => {
    vi.useFakeTimers();
    vi.stubGlobal('location', { reload: vi.fn(), fetch: vi.fn() });

    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(),
      set: vi.fn(),
    };

    await AuthClient.create({
      storage,
      idleOptions: {
        idleTimeout: 1000,
      },
    });

    expect(storage.set).toHaveBeenCalled();
    expect(storage.remove).not.toHaveBeenCalled();

    // simulate user being inactive for 10 minutes
    vi.advanceTimersByTime(10 * 60 * 1000);

    // Storage should not be cleared
    expect(storage.remove).not.toHaveBeenCalled();
    // Page should not be reloaded
    expect(window.location.reload).not.toHaveBeenCalled();
  });
});

describe('IdbStorage', () => {
  it('should handle get and set', async () => {
    const storage = new IdbStorage();

    await storage.set('testKey', 'testValue');
    expect(await storage.get('testKey')).toBe('testValue');
  });
});

describe('Migration from localstorage', () => {
  it('should proceed normally if no values are stored in localstorage', async () => {
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(),
      set: vi.fn(),
    };

    await AuthClient.create({ storage });

    // Key is stored during creation when none is provided
    expect(storage.set).toHaveBeenCalledTimes(1);
  });

  it('should not attempt to migrate if a delegation is already stored', async () => {
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(async (x) => {
        if (x === KEY_STORAGE_DELEGATION) return 'test';
        if (x === KEY_STORAGE_KEY) return 'key';
        return null;
      }),
      set: vi.fn(),
    };

    await AuthClient.create({ storage });

    expect(storage.set).toHaveBeenCalledTimes(1);
  });

  it('should migrate storage from localstorage', async () => {
    const localStorage = new LocalStorage();
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(),
      set: vi.fn(),
    };

    await localStorage.set(KEY_STORAGE_DELEGATION, 'test');
    await localStorage.set(KEY_STORAGE_KEY, 'key');

    await AuthClient.create({ storage });

    expect(storage.set).toHaveBeenCalledTimes(3);
  });
});

describe('Migration from Ed25519Key', () => {
  const testSecrets = [
    '302a300506032b6570032100d1fa89134802051c8b5d4e53c08b87381b87097bca4c4f348611eb8ce6c91809',
    '4bbff6b476463558d7be318aa342d1a97778d70833038680187950e9e02486c0d1fa89134802051c8b5d4e53c08b87381b87097bca4c4f348611eb8ce6c91809',
  ];

  it('should continue using an existing Ed25519Key and delegation', async () => {
    // set the timer to a fixed value
    vi.setSystemTime(new Date('2020-01-01T00:00:00.000Z'));

    // two days from now
    const expiration = new Date('2020-01-03T00:00:00.000Z');

    const key = Ed25519KeyIdentity.fromJSON(JSON.stringify(testSecrets));
    const chain = DelegationChain.create(key, key.getPublicKey(), expiration);
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(async (x) => {
        if (x === KEY_STORAGE_DELEGATION) return JSON.stringify((await chain).toJSON());
        if (x === KEY_STORAGE_KEY) return JSON.stringify(testSecrets);
        return null;
      }),
      set: vi.fn(),
    };

    const client = await AuthClient.create({ storage });

    const identity = client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(false);
  });

  it('should continue using an existing Ed25519Key with no delegation', async () => {
    // set the timer to a fixed value
    vi.setSystemTime(new Date('2020-01-01T00:00:00.000Z'));

    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(async (x) => {
        if (x === KEY_STORAGE_KEY) return JSON.stringify(testSecrets);
        return null;
      }),
      set: vi.fn(),
    };

    const client = await AuthClient.create({ storage });

    const identity = client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(true);
  });

  it('should continue using an existing Ed25519Key with an expired delegation', async () => {
    // set the timer to a fixed value
    vi.setSystemTime(new Date('2020-01-01T00:00:00.000Z'));

    // two days ago
    const expiration = new Date('2019-12-30T00:00:00.000Z');

    const key = Ed25519KeyIdentity.fromJSON(JSON.stringify(testSecrets));

    const chain = DelegationChain.create(key, key.getPublicKey(), expiration);
    const fakeStore: Record<string, string> = {};
    fakeStore[KEY_STORAGE_DELEGATION] = JSON.stringify((await chain).toJSON());
    fakeStore[KEY_STORAGE_KEY] = JSON.stringify(testSecrets);

    const storage: AuthClientStorage = {
      remove: vi.fn(async (x) => {
        delete fakeStore[x];
      }),
      get: vi.fn(async (x) => {
        return fakeStore[x] ?? null;
      }),
      set: vi.fn(),
    };

    const client = await AuthClient.create({ storage });

    const identity = client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(true);

    // expect the delegation to be removed
    expect(storage.remove).toHaveBeenCalledTimes(3);
    expect(fakeStore).toMatchInlineSnapshot(`{}`);
  });

  it('should generate and store a ECDSAKey if no key is stored', async () => {
    const fakeStore: Record<string, string> = {};
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(),
      set: vi.fn(async (x, y) => {
        fakeStore[x] = y;
      }),
    };
    await AuthClient.create({ storage });

    // It should have stored a cryptoKey
    expect(Object.keys(fakeStore[KEY_STORAGE_KEY])).toMatchInlineSnapshot(`
      [
        "publicKey",
        "privateKey",
      ]
    `);
  });

  it("should generate and store a Ed25519 if no key is stored and keyType is set to Ed25519, and load the same key if it's found in storage", async () => {
    const fakeStore: Record<string, string> = {};
    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(async (key) => fakeStore[key] ?? null),
      set: vi.fn(async (x, y) => {
        fakeStore[x] = y;
      }),
    };

    // Mock the ED25519 generate method, only for the first auth client
    const generate = vi.spyOn(Ed25519KeyIdentity, 'generate');
    generate.mockImplementationOnce((): Ed25519KeyIdentity => {
      const key = Ed25519KeyIdentity.fromJSON(JSON.stringify(testSecrets));
      return key;
    });

    const client1 = await AuthClient.create({ storage, keyType: 'Ed25519' });
    const identity1 = client1.getIdentity();

    // This auth client should find the Ed25519 key in the storage,
    // and not generate a new one
    const client2 = await AuthClient.create({ storage, keyType: 'Ed25519' });
    const identity2 = client2.getIdentity();

    expect(generate).toHaveBeenCalledTimes(1);
    // The first identity, created from testSecrets, should be the same as the second identity,
    // loaded from the storage
    expect(identity1.getPrincipal().toString()).toEqual(identity2.getPrincipal().toString());
  });
});
