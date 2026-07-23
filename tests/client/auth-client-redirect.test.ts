import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthClient } from '../../src/client/auth-client.ts';
import { IdleManager } from '../../src/client/idle-manager.ts';
import type { AuthClientStorage, StoredKey } from '../../src/client/storage.ts';
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
const PENDING_KEY_PREFIX = 'ic-auth-pending-key:';

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** A shared in-memory storage so two "loads" see the same persisted state. */
function createSharedStorage(): AuthClientStorage & { map: Map<string, StoredKey> } {
  const map = new Map<string, StoredKey>();
  return {
    map,
    get: async (key) => map.get(key) ?? null,
    set: async (key, value) => void map.set(key, value),
    remove: async (key) => void map.delete(key),
  };
}

async function delegationBody() {
  const key = Ed25519KeyIdentity.generate();
  const chain = await DelegationChain.create(key, key.getPublicKey(), new Date(Date.now() + 3.6e6));
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

const SIGN_IN_BODY = await delegationBody();

function handleSignIn(transport: FakeUrlTransport): void {
  transport.onRequest((req) => {
    if (req.method !== 'icrc34_delegation' || req.id == null) return;
    return { jsonrpc: '2.0', id: req.id, ...SIGN_IN_BODY };
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

const pendingSlots = (storage: ReturnType<typeof createSharedStorage>) =>
  [...storage.map.keys()].filter((k) => k.startsWith(PENDING_KEY_PREFIX));

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
  it('routes sign-in through the URL transport and cleans up the pending key', async () => {
    const storage = createSharedStorage();
    const client = new AuthClient({ transport: 'redirect', storage });
    handleSignIn(FakeUrlTransport.last());

    const identity = await client.signIn();

    expect(identity.getPrincipal().isAnonymous()).toBe(false);
    expect(FakeUrlTransport.last().requests[0]?.method).toBe('icrc34_delegation');
    // The key id was journaled via `memoize`, and the pending key was removed
    // once the delegation was persisted.
    expect(FakeUrlTransport.journal).toHaveLength(1);
    expect(pendingSlots(storage)).toEqual([]);
  });

  it('derives the callback URL from the current location', () => {
    new AuthClient({ transport: 'redirect' });
    // origin + pathname of the current page, with any query/fragment dropped.
    expect(FakeUrlTransport.last().options.callbackUrl).toBe(CALLBACK_URL);
  });

  it('reuses the session key across the redirect', async () => {
    const storage = createSharedStorage();

    // Load 1: navigates to the signer and never returns in-context.
    FakeUrlTransport.nextRespond = false;
    const client1 = new AuthClient({ transport: 'redirect', storage });
    handleSignIn(FakeUrlTransport.last());
    const pending1 = client1.signIn().catch(() => undefined); // stays pending
    await flush();

    const load1 = FakeUrlTransport.last();
    expect(load1.requests[0]?.method).toBe('icrc34_delegation');
    expect(pendingSlots(storage)).toHaveLength(1); // key persisted for the return
    const publicKey1 = load1.requests[0]?.params?.publicKey;

    // Load 2: the signer returns; the flow replays and completes.
    FakeUrlTransport.nextRespond = true;
    const client2 = new AuthClient({ transport: 'redirect', storage });
    handleSignIn(FakeUrlTransport.last());
    const identity = await client2.signIn();

    const load2 = FakeUrlTransport.last();
    expect(identity.getPrincipal().isAnonymous()).toBe(false);
    // The delegation on the return load was requested for the SAME key that
    // load 1 generated — not a fresh one that would not match.
    expect(load2.requests[0]?.params?.publicKey).toBe(publicKey1);
    expect(pendingSlots(storage)).toEqual([]); // cleaned up on completion
    void pending1;
  });

  it('memoize journals a caller value and replays it across the redirect', async () => {
    const produce = vi.fn(() => 'https://relying.example.com/next');

    // Load 1: the value is produced and journaled.
    const client1 = new AuthClient({ transport: 'redirect', storage: createSharedStorage() });
    const v1 = await client1.memoize(produce);

    // Load 2 (shared journal): the value replays without re-running produce.
    const client2 = new AuthClient({ transport: 'redirect', storage: createSharedStorage() });
    const v2 = await client2.memoize(produce);

    expect(v1).toBe('https://relying.example.com/next');
    expect(v2).toBe(v1);
    expect(produce).toHaveBeenCalledOnce(); // not re-run on the return load
  });
});

describe('AuthClient redirect (UrlTransport) requestAttributes', () => {
  it('memoizes the nonce and forwards it as base64', async () => {
    const client = new AuthClient({ transport: 'redirect', storage: createSharedStorage() });
    handleAttributes(FakeUrlTransport.last());

    const nonce = new Uint8Array(32).fill(3);
    const thunk = vi.fn(() => Promise.resolve(nonce));
    await client.requestAttributes({ keys: ['email'], nonce: thunk });

    expect(thunk).toHaveBeenCalledOnce();
    expect(FakeUrlTransport.last().requests[0]?.params?.nonce).toBe(toBase64(nonce));
    expect(FakeUrlTransport.journal).toEqual([toBase64(nonce)]); // journaled as base64
  });

  it('reuses the memoized nonce across the redirect instead of re-fetching', async () => {
    const storage = createSharedStorage();
    let counter = 0;
    const thunk = vi.fn(() => Promise.resolve(new Uint8Array(32).fill(++counter))); // fresh each call

    // Load 1: fetches the nonce, sends the request, then navigates away.
    FakeUrlTransport.nextRespond = false;
    const client1 = new AuthClient({ transport: 'redirect', storage });
    handleAttributes(FakeUrlTransport.last());
    const pending1 = client1.requestAttributes({ keys: ['email'], nonce: thunk }).catch(() => null);
    await flush();
    const nonce1 = FakeUrlTransport.last().requests[0]?.params?.nonce;

    // Load 2: the flow replays; the nonce must be the one signed against.
    FakeUrlTransport.nextRespond = true;
    const client2 = new AuthClient({ transport: 'redirect', storage });
    handleAttributes(FakeUrlTransport.last());
    await client2.requestAttributes({ keys: ['email'], nonce: thunk });

    expect(thunk).toHaveBeenCalledOnce(); // not re-fetched on the return load
    expect(FakeUrlTransport.last().requests[0]?.params?.nonce).toBe(nonce1);
    void pending1;
  });
});
