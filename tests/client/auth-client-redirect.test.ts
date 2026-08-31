import type { PublicKey } from '@icp-sdk/core/agent';
import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthClient } from '../../src/client/auth-client.ts';
import { PENDING_SLOT } from '../../src/client/credential-storage.ts';
import { IdleManager } from '../../src/client/idle-manager.ts';
import { LocalCredentialStorage } from '../../src/client/local-credential-storage.ts';
import { MemoryCredentialStorage } from '../../src/client/memory-credential-storage.ts';
import { SharedMemoryCredentialStorage } from '../../src/client/shared-memory-credential-storage.ts';
import { FakeUrlTransport } from './fake-url-transport.ts';

// Redirect mode selects `UrlTransport` from `@icp-sdk/signer/web`; swap it for
// an in-memory fake so the flow can be driven without a real page navigation.
// `PostMessageTransport` is left as the real export — these tests never use it.
vi.mock('@icp-sdk/signer/web', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@icp-sdk/signer/web')>();
  const { FakeUrlTransport } = await import('./fake-url-transport.ts');
  return { ...actual, UrlTransport: FakeUrlTransport };
});

const CALLBACK_ORIGIN = 'https://relying.example.com';
const CALLBACK_PATH = '/connect';
const CALLBACK_URL = `${CALLBACK_ORIGIN}${CALLBACK_PATH}`;

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

/**
 * A durable store, which is what a redirect needs: the key is written before the
 * navigation and read again on the load that comes back, so a store the document
 * takes with it could not finish the flow. One instance stands in for the two
 * "loads" here, and `localStorage` is cleared between tests.
 */
function createDurableStorage(): LocalCredentialStorage {
  return new LocalCredentialStorage();
}

// A delegation chain delegating to the requested session key, as a conformant
// signer returns — the signer's returned-chain validation (>= 5.6.1) requires
// the leaf to match the requested key.
async function delegationBody(publicKey: string) {
  const to = { toDer: () => fromBase64(publicKey) } as unknown as PublicKey;
  const chain = await DelegationChain.create(
    Ed25519KeyIdentity.generate(),
    to,
    new Date(Date.now() + 3.6e6),
  );
  return {
    result: {
      publicKey: toBase64(new Uint8Array(chain.publicKey)),
      signerDelegation: chain.delegations.map((sd) => ({
        delegation: {
          pubkey: toBase64(new Uint8Array(sd.delegation.pubkey)),
          expiration: sd.delegation.expiration.toString(),
          targets: sd.delegation.targets?.map((t) => t.toText()),
        },
        signature: toBase64(new Uint8Array(sd.signature)),
      })),
    },
  };
}

function handleSignIn(transport: FakeUrlTransport): void {
  transport.onRequest(async (req) => {
    if (req.method !== 'icrc34_delegation' || req.id == null) return;
    return {
      jsonrpc: '2.0',
      id: req.id,
      ...(await delegationBody(req.params?.publicKey as string)),
    };
  });
}

function handleAttributes(transport: FakeUrlTransport): void {
  transport.onRequest((req) => {
    if (req.method !== 'ii-icrc3-attributes' || req.id == null) return;
    return { jsonrpc: '2.0', id: req.id, result: { data: btoa('hi'), signature: btoa('sig') } };
  });
}

const flush = async () => {
  for (let i = 0; i < 15; i++) await new Promise((r) => setTimeout(r, 0));
};

const hasPendingKey = async (storage: LocalCredentialStorage) =>
  (await storage.get(PENDING_SLOT)) !== null;

beforeEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  localStorage.clear();
  FakeUrlTransport.reset();
  // Redirect mode derives its callback URL from the current location, so give
  // location a concrete origin + pathname (plus reload for idle teardown).
  vi.stubGlobal('location', {
    origin: CALLBACK_ORIGIN,
    pathname: CALLBACK_PATH,
    reload: vi.fn(),
  });
});

afterEach(async () => {
  try {
    IdleManager.create().exit();
  } catch {
    // no-op if already torn down
  }
  await new Promise((r) => setTimeout(r, 0));
  localStorage.clear();
});

describe('AuthClient redirect (UrlTransport) sign-in', () => {
  it('refuses a redirect where no medium can answer for the key', async () => {
    const client = new AuthClient({
      transport: 'redirect',
      credentialStorage: new MemoryCredentialStorage(),
    });

    // Refused before navigating rather than on the load that comes back: the key
    // is written before the redirect and read after it, and a store the document
    // takes with it can do neither.
    await expect(client.signIn()).rejects.toThrow(/survives the navigation/);
    expect(FakeUrlTransport.last()?.requests ?? []).toHaveLength(0);
  });

  it('allows a redirect where a peer tab can answer for the key', async () => {
    const storage = new SharedMemoryCredentialStorage();
    const client = new AuthClient({ transport: 'redirect', credentialStorage: storage });
    handleSignIn(FakeUrlTransport.last());

    // Shared but not durable: the key does not survive the navigation, but another
    // tab of this origin holds it and answers, so the flow proceeds rather than
    // being refused for its medium.
    const identity = await client.signIn();

    expect(identity.getPrincipal().isAnonymous()).toBe(false);
    storage.close();
  });

  it('routes sign-in through the URL transport and cleans up the pending key', async () => {
    const storage = createDurableStorage();
    const client = new AuthClient({ transport: 'redirect', credentialStorage: storage });
    handleSignIn(FakeUrlTransport.last());

    const identity = await client.signIn();

    expect(identity.getPrincipal().isAnonymous()).toBe(false);
    expect(FakeUrlTransport.last().requests[0]?.method).toBe('icrc34_delegation');
    // The flow journals values that replay across the redirect: the (unset)
    // derivation origin from construction, and the key-acquisition step, which
    // both holds the batch so the delegation isn't split off from a concurrent
    // request and records which key this ceremony started with. The pending key
    // is removed once the session is stored.
    expect(FakeUrlTransport.journal).toHaveLength(2);
    expect(FakeUrlTransport.journal[0]).toBeUndefined(); // derivation origin unset
    expect(await hasPendingKey(storage)).toBe(false);
  });

  it('completes sign-in even if pending-key cleanup fails', async () => {
    const storage = createDurableStorage();
    const remove = storage.remove.bind(storage);
    storage.remove = async (slot) => {
      if (slot === PENDING_SLOT) throw new Error('storage unavailable');
      return remove(slot);
    };

    const client = new AuthClient({ transport: 'redirect', credentialStorage: storage });
    handleSignIn(FakeUrlTransport.last());
    const identity = await client.signIn();

    // Cleanup of the completed flow's pending key failed, but auth succeeded.
    expect(identity.getPrincipal().isAnonymous()).toBe(false);
  });

  it('journals the derivation origin so it survives the redirect', async () => {
    const storage = createDurableStorage();
    const DERIVATION = 'https://derivation.example.com';

    // Load 1: derivation origin supplied — forwarded on the request and journaled.
    FakeUrlTransport.nextRespond = false;
    const client1 = new AuthClient({
      transport: 'redirect',
      derivationOrigin: DERIVATION,
      credentialStorage: storage,
    });
    handleSignIn(FakeUrlTransport.last());
    const pending1 = client1.signIn().catch(() => undefined); // navigates away
    await flush();
    expect(FakeUrlTransport.last().requests[0]?.params?.icrc95DerivationOrigin).toBe(DERIVATION);

    // Load 2: the callback URL has no query, so no derivation origin is passed
    // to the reconstructed client — the memoized value replays, so the request
    // still carries the original derivation origin.
    FakeUrlTransport.nextRespond = true;
    const client2 = new AuthClient({ transport: 'redirect', credentialStorage: storage });
    handleSignIn(FakeUrlTransport.last());
    await client2.signIn();
    expect(FakeUrlTransport.last().requests[0]?.params?.icrc95DerivationOrigin).toBe(DERIVATION);
    void pending1;
  });

  it('derives the callback URL from the current location', () => {
    new AuthClient({ transport: 'redirect' });
    // origin + pathname of the current page, with any query/fragment dropped.
    expect(FakeUrlTransport.last().options.callbackUrl).toBe(CALLBACK_URL);
  });

  it('reuses the session key across the redirect', async () => {
    const storage = createDurableStorage();

    // Load 1: navigates to the signer and never returns in-context.
    FakeUrlTransport.nextRespond = false;
    const client1 = new AuthClient({ transport: 'redirect', credentialStorage: storage });
    handleSignIn(FakeUrlTransport.last());
    const pending1 = client1.signIn().catch(() => undefined); // stays pending
    await flush();

    const load1 = FakeUrlTransport.last();
    expect(load1.requests[0]?.method).toBe('icrc34_delegation');
    expect(await hasPendingKey(storage)).toBe(true); // persisted for the return
    const publicKey1 = load1.requests[0]?.params?.publicKey;

    // Load 2: the signer returns; the flow replays and completes.
    FakeUrlTransport.nextRespond = true;
    const client2 = new AuthClient({ transport: 'redirect', credentialStorage: storage });
    handleSignIn(FakeUrlTransport.last());
    const identity = await client2.signIn();

    const load2 = FakeUrlTransport.last();
    expect(identity.getPrincipal().isAnonymous()).toBe(false);
    // The delegation on the return load was requested for the SAME key that
    // load 1 generated — not a fresh one that would not match.
    expect(load2.requests[0]?.params?.publicKey).toBe(publicKey1);
    expect(await hasPendingKey(storage)).toBe(false); // cleaned up on completion
    void pending1;
  });

  it('refuses to finish when another sign-in took the pending slot', async () => {
    const storage = createDurableStorage();

    // Load 1: navigates to the signer and never returns in-context.
    FakeUrlTransport.nextRespond = false;
    const client1 = new AuthClient({ transport: 'redirect', credentialStorage: storage });
    handleSignIn(FakeUrlTransport.last());
    const pending1 = client1.signIn().catch(() => undefined);
    await flush();

    // Another ceremony in this browser takes the slot while the first is away.
    await storage.set(PENDING_SLOT, { identity: await storage.create() });

    // Load 2: the delegation replayed from the journal was minted for a key
    // that is no longer there, so the flow cannot finish.
    FakeUrlTransport.nextRespond = true;
    const client2 = new AuthClient({ transport: 'redirect', credentialStorage: storage });
    handleSignIn(FakeUrlTransport.last());

    await expect(client2.signIn()).rejects.toThrow(/superseded/);
    void pending1;
  });

  it('memoize journals a caller value and replays it across the redirect', async () => {
    const produce = vi.fn(() => 'https://relying.example.com/next');

    // Load 1: the value is produced and journaled.
    const client1 = new AuthClient({
      transport: 'redirect',
      credentialStorage: createDurableStorage(),
    });
    const v1 = await client1.memoize(produce);

    // Load 2 (shared journal): the value replays without re-running produce.
    const client2 = new AuthClient({
      transport: 'redirect',
      credentialStorage: createDurableStorage(),
    });
    const v2 = await client2.memoize(produce);

    expect(v1).toBe('https://relying.example.com/next');
    expect(v2).toBe(v1);
    expect(produce).toHaveBeenCalledOnce(); // not re-run on the return load
  });
});

describe('AuthClient redirect (UrlTransport) requestAttributes', () => {
  it('memoizes the nonce and forwards it as base64', async () => {
    const client = new AuthClient({
      transport: 'redirect',
      credentialStorage: createDurableStorage(),
    });
    handleAttributes(FakeUrlTransport.last());

    const nonce = new Uint8Array(32).fill(3);
    const thunk = vi.fn(() => Promise.resolve(nonce));
    await client.requestAttributes({ keys: ['email'], nonce: thunk });

    expect(thunk).toHaveBeenCalledOnce();
    expect(FakeUrlTransport.last().requests[0]?.params?.nonce).toBe(toBase64(nonce));
    // Slot 0 is the (unset) derivation origin journaled at construction; slot 1
    // is the nonce, journaled as base64.
    expect(FakeUrlTransport.journal).toEqual([undefined, toBase64(nonce)]);
  });

  it('reuses the memoized nonce across the redirect instead of re-fetching', async () => {
    const storage = createDurableStorage();
    let counter = 0;
    const thunk = vi.fn(() => Promise.resolve(new Uint8Array(32).fill(++counter))); // fresh each call

    // Load 1: fetches the nonce, sends the request, then navigates away.
    FakeUrlTransport.nextRespond = false;
    const client1 = new AuthClient({ transport: 'redirect', credentialStorage: storage });
    handleAttributes(FakeUrlTransport.last());
    const pending1 = client1.requestAttributes({ keys: ['email'], nonce: thunk }).catch(() => null);
    await flush();
    const nonce1 = FakeUrlTransport.last().requests[0]?.params?.nonce;

    // Load 2: the flow replays; the nonce must be the one signed against.
    FakeUrlTransport.nextRespond = true;
    const client2 = new AuthClient({ transport: 'redirect', credentialStorage: storage });
    handleAttributes(FakeUrlTransport.last());
    await client2.requestAttributes({ keys: ['email'], nonce: thunk });

    expect(thunk).toHaveBeenCalledOnce(); // not re-fetched on the return load
    expect(FakeUrlTransport.last().requests[0]?.params?.nonce).toBe(nonce1);
    void pending1;
  });
});
