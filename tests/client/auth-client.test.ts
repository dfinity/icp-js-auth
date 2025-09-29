import { Actor, type AgentError, HttpAgent } from '@icp-sdk/core/agent';
import { IDL } from '@icp-sdk/core/candid';
import { DelegationChain, ECDSAKeyIdentity, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';
import { AuthClient, ERROR_USER_INTERRUPT } from '../../src/client/auth-client.ts';
import {
  type AuthClientStorage,
  IdbStorage,
  KEY_STORAGE_DELEGATION,
  KEY_STORAGE_KEY,
  LocalStorage,
  type StoredKey,
} from '../../src/client/storage.ts';

/**
 * A class for mocking the IDP service.
 */
class IdpMock {
  constructor(
    private readonly eventListener: (event: unknown) => void,
    private readonly origin: string,
  ) {}

  ready(origin?: string) {
    this.send(
      {
        kind: 'authorize-ready',
      },
      origin,
    );
  }

  send(message: unknown, origin?: string) {
    this.eventListener({
      origin: origin ?? this.origin,
      data: message,
    });
  }
}

beforeEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
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

  it('should log out after idle and reload the window by default', async () => {
    vi.useFakeTimers();

    setup({
      onAuthRequest: () => {
        // Send a valid request.
        idpMock.send({
          kind: 'authorize-client-success',
          delegations: [
            {
              delegation: {
                pubkey: Uint8Array.from([]),
                expiration: BigInt(0),
              },
              signature: Uint8Array.from([]),
            },
          ],
          userPublicKey: Uint8Array.from([]),
        });
      },
    });
    vi.stubGlobal('location', { reload: vi.fn(), fetch: vi.fn() });

    const storage: AuthClientStorage = {
      remove: vi.fn(),
      get: vi.fn(),
      set: vi.fn(),
    };

    // setup auth client
    const test = await AuthClient.create({
      storage,
      idleOptions: {
        idleTimeout: 1000,
      },
    });

    // Test login flow
    const onSuccess = vi.fn();
    test.login({ onSuccess });

    idpMock.ready();

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

    setup({
      onAuthRequest: () => {
        // Send a valid request.
        idpMock.send({
          kind: 'authorize-client-success',
          delegations: [
            {
              delegation: {
                pubkey: Uint8Array.from([]),
                expiration: BigInt(0),
              },
              signature: Uint8Array.from([]),
            },
          ],
          userPublicKey: Uint8Array.from([]),
        });
      },
    });
    vi.stubGlobal('location', { reload: vi.fn(), fetch: vi.fn() });

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

    // Test login flow
    await test.login();
    idpMock.ready();

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
    setup({
      onAuthRequest: () => {
        // Send a valid request.
        idpMock.send({
          kind: 'authorize-client-success',
          delegations: [
            {
              delegation: {
                pubkey: Uint8Array.from([]),
                expiration: BigInt(0),
              },
              signature: Uint8Array.from([]),
            },
          ],
          userPublicKey: Uint8Array.from([]),
        });
      },
    });
    vi.stubGlobal('location', { reload: vi.fn(), fetch: vi.fn() });

    const idleCb = vi.fn();
    const test = await AuthClient.create({
      idleOptions: {
        idleTimeout: 1000,
        onIdle: idleCb,
      },
    });

    vi.useFakeTimers();

    test.login();
    idpMock.ready();

    // simulate user being inactive for 10 minutes
    vi.advanceTimersByTime(10 * 60 * 1000);

    expect(window.location.reload).not.toHaveBeenCalled();
    expect(idleCb).toHaveBeenCalled();
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

  it('should not set up an idle timer if the client is not logged in', async () => {
    vi.useFakeTimers();

    setup({
      onAuthRequest: () => {
        // Send a valid request.
        idpMock.send({
          kind: 'authorize-client-success',
          delegations: [
            {
              delegation: {
                pubkey: Uint8Array.from([]),
                expiration: BigInt(0),
              },
              signature: Uint8Array.from([]),
            },
          ],
          userPublicKey: Uint8Array.from([]),
        });
      },
    });
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

// A minimal interface of our interactions with the Window object of the IDP.
interface IdpWindow {
  postMessage: Mock;
  close(): void;
  closed: boolean;
}

let idpWindow: IdpWindow;
let idpMock: IdpMock;
function setup(options?: { onAuthRequest?: () => void }) {
  // Set the event handler.
  global.addEventListener = vi.fn((_, callback) => {
    idpMock = new IdpMock(callback, 'https://identity.internetcomputer.org');
  });

  // Mock window.open and window.postMessage since we can't open windows here.
  vi.stubGlobal(
    'open',
    vi.fn(() => {
      idpWindow = {
        postMessage: vi.fn((message) => {
          if (message.kind === 'authorize-client') {
            options?.onAuthRequest?.();
          }
        }),
        close: vi.fn(() => {
          idpWindow.closed = true;
        }),
        closed: false,
      };
      return idpWindow;
    }),
  );
}

describe('Auth Client login', () => {
  it('should open a window with the IDP url', async () => {
    setup();
    const client = await AuthClient.create();
    // Try without #authorize hash.
    await client.login({ identityProvider: 'http://127.0.0.1' });
    expect(globalThis.open).toHaveBeenCalledWith(
      'http://127.0.0.1/#authorize',
      'idpWindow',
      undefined,
    );

    // Try with #authorize hash.
    globalThis.open = vi.fn();
    await client.login({ identityProvider: 'http://127.0.0.1#authorize' });
    expect(globalThis.open).toHaveBeenCalledWith(
      'http://127.0.0.1/#authorize',
      'idpWindow',
      undefined,
    );

    // Default url
    globalThis.open = vi.fn();
    await client.login();
    expect(globalThis.open).toHaveBeenCalledWith(
      'https://identity.internetcomputer.org/#authorize',
      'idpWindow',
      undefined,
    );

    // Default custom window.open feature
    globalThis.open = vi.fn();
    await client.login({
      windowOpenerFeatures: 'toolbar=0,location=0,menubar=0',
    });
    expect(globalThis.open).toHaveBeenCalledWith(
      'https://identity.internetcomputer.org/#authorize',
      'idpWindow',
      'toolbar=0,location=0,menubar=0',
    );
  });

  it('should login with a derivation origin', async () => {
    setup();
    const client = await AuthClient.create();
    // Try without #authorize hash.
    await client.login({
      identityProvider: 'http://127.0.0.1',
      derivationOrigin: 'http://127.0.0.1:1234',
    });

    idpMock.ready('http://127.0.0.1');

    const call = idpWindow.postMessage.mock.calls[0][0];
    expect(call.derivationOrigin).toBe('http://127.0.0.1:1234');
  });

  it('should ignore authorize-ready events with bad origin', async () => {
    setup();
    const client = await AuthClient.create();
    await client.login();

    // Send an authorize-ready message with a bad origin. It should _not_ result
    // in a message sent back to the IDP.
    idpMock.ready('bad origin');

    // No response to the IDP canister.
    expect(idpWindow.postMessage).not.toHaveBeenCalled();
  });

  it('should respond to authorize-ready events with correct origin', async () => {
    setup();
    const client = await AuthClient.create();
    await client.login();

    // Send an authorize-ready message with the correct origin.
    idpMock.ready();

    // A response should be sent to the IDP.
    expect(idpWindow.postMessage).toHaveBeenCalled();
  });

  it('should call onError and close the IDP window on failure', async () => {
    setup({
      onAuthRequest: () => {
        // Send a failure message.
        idpMock.send({
          kind: 'authorize-client-failure',
          text: 'mock error message',
        });
      },
    });
    const client = await AuthClient.create();
    const failureFunc = vi.fn();
    await client.login({ onError: failureFunc });

    idpMock.ready();

    expect(failureFunc).toHaveBeenCalledWith('mock error message');
    expect(idpWindow.close).toHaveBeenCalled();
  });

  it('should call onError if received an invalid success message', () =>
    new Promise((done) => {
      setup({
        onAuthRequest: () => {
          idpMock.send({
            kind: 'authorize-client-success',
          });
        },
      });

      AuthClient.create()
        .then((client) => {
          const onError = () => {
            expect(idpWindow.close).toHaveBeenCalled();

            client.logout().then(done);
          };

          return client.login({ onError: onError });
        })
        .then(() => {
          idpMock.ready();
        });
    }));

  it('should call onSuccess if received a valid success message', () =>
    new Promise((done) => {
      setup({
        onAuthRequest: () => {
          // Send a valid request.
          idpMock.send({
            kind: 'authorize-client-success',
            delegations: [
              {
                delegation: {
                  pubkey: Uint8Array.from([]),
                  expiration: BigInt(0),
                },
                signature: Uint8Array.from([]),
              },
            ],
            userPublicKey: Uint8Array.from([]),
          });
        },
      });

      AuthClient.create()
        .then((client) => {
          const onSuccess = () => {
            expect(idpWindow.close).toHaveBeenCalled();

            client.logout().then(done);
          };

          return client.login({ onSuccess: onSuccess });
        })
        .then(() => {
          idpMock.ready();
        });
    }));

  it('should call onError if the user closed the IDP window', async () => {
    setup();
    vi.useRealTimers();
    const client = await AuthClient.create({ idleOptions: { disableIdle: true } });

    await expect(
      new Promise<void>((onSuccess, onError) =>
        (async () => {
          await client.login({ onSuccess, onError });
          idpWindow.close();
        })(),
      ),
    ).rejects.toMatch(ERROR_USER_INTERRUPT);
  });

  it('should overwrite stored Ed25519 key with in-memory key on login', async () => {
    setup({
      onAuthRequest: () => {
        idpMock.send({
          kind: 'authorize-client-success',
          delegations: [
            {
              delegation: {
                pubkey: Uint8Array.from([]),
                expiration: BigInt(0),
              },
              signature: Uint8Array.from([]),
            },
          ],
          userPublicKey: Uint8Array.from([]),
        });
      },
    });

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

    await new Promise<void>((resolve, reject) => {
      client.login({
        onSuccess: resolve,
        onError: reject,
      });
      idpMock.ready();
    });

    expect(fakeStore[KEY_STORAGE_KEY]).toEqual(initialKey);
    expect(fakeStore[KEY_STORAGE_KEY]).not.toEqual(overwrittenKey);
  });

  it('should overwrite stored ECDSA key pair with in-memory key on login', async () => {
    setup({
      onAuthRequest: () => {
        idpMock.send({
          kind: 'authorize-client-success',
          delegations: [
            {
              delegation: {
                pubkey: Uint8Array.from([]),
                expiration: BigInt(0),
              },
              signature: Uint8Array.from([]),
            },
          ],
          userPublicKey: Uint8Array.from([]),
        });
      },
    });

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

    await new Promise<void>((resolve, reject) => {
      client.login({ onSuccess: resolve, onError: reject });
      idpMock.ready();
    });

    const restored = fakeStore[KEY_STORAGE_KEY] as CryptoKeyPair;
    // Expect the same key references as initially stored
    expect(restored.publicKey).toBe(initialKeyPair.publicKey);
    expect(restored.privateKey).toBe(initialKeyPair.privateKey);
    expect(restored.privateKey).not.toBe(overwrittenKeyPair.privateKey);
    expect(restored.publicKey).not.toBe(overwrittenKeyPair.publicKey);
  });

  it('should use the loginOptions passed to the create method', async () => {
    setup();
    const client = await AuthClient.create({
      loginOptions: {
        identityProvider: 'http://my-local-website.localhost:8080',
        maxTimeToLive: BigInt(1000),
        customValues: { test: 'val' },
      },
    });

    await client.login();

    idpMock.ready('http://my-local-website.localhost:8080');

    expect(idpWindow.postMessage).toHaveBeenCalledTimes(1);
    const args = idpWindow.postMessage.mock.calls[0][0];

    expect(globalThis.open).toHaveBeenCalledWith(
      'http://my-local-website.localhost:8080/#authorize',
      'idpWindow',
      undefined,
    );
    expect(args.maxTimeToLive).toEqual(BigInt(1000));
    expect(args.test).toEqual('val');
  });

  it('should merge the loginOptions passed to the create method and the login method', async () => {
    setup();
    const client = await AuthClient.create({
      loginOptions: {
        identityProvider: 'http://my-local-website.localhost:8080',
        derivationOrigin: 'http://another-local-website.localhost:8080',
        customValues: { test: { inner: 'val' } },
      },
    });

    await client.login({
      identityProvider: 'http://replaced.localhost:8080',
      customValues: { test: 'another-val' },
    });

    idpMock.ready('http://replaced.localhost:8080');

    expect(idpWindow.postMessage).toHaveBeenCalledTimes(1);
    const args = idpWindow.postMessage.mock.calls[0][0];

    expect(globalThis.open).toHaveBeenCalledWith(
      'http://replaced.localhost:8080/#authorize',
      'idpWindow',
      undefined,
    );
    expect(args.test).toEqual('another-val');
    expect(args.derivationOrigin).toEqual('http://another-local-website.localhost:8080');
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
    // set the jest timer to a fixed value
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
    expect(identity).toMatchSnapshot();
  });

  it('should continue using an existing Ed25519Key with no delegation', async () => {
    // set the jest timer to a fixed value
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
    // set the jest timer to a fixed value
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
    // It should have stored a cryptoKey
    expect(fakeStore[KEY_STORAGE_KEY]).toMatchSnapshot();
    // The first identity, created from testSecrets, should be the same as the second identity,
    // loaded from the storage
    expect(identity1.getPrincipal().toString()).toEqual(identity2.getPrincipal().toString());
  });
});
