import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { slotsFor } from '../../src/client/slots.ts';

/** The bare names, which is what a client with no namespace writes under. */
const SLOTS = slotsFor();

import { SharedMemoryCredentialStorage } from '../../src/client/shared-memory-credential-storage.ts';

/**
 * A Web Locks implementation for one process, because jsdom has none and this
 * store's waiting is expressed entirely in locks.
 *
 * Exclusive only, queued in arrival order, and `query()` reports what is held —
 * which is all this store asks of the API.
 */
class FakeLockManager {
  #held = new Map<string, Promise<unknown>>();

  request<T>(name: string, _options: unknown, callback: () => T | Promise<T>): Promise<T> {
    const previous = this.#held.get(name) ?? Promise.resolve();
    const run = previous.then(async () => await callback());
    // Held until the callback settles, and released whether it resolved or threw.
    this.#held.set(
      name,
      run.catch(() => undefined),
    );
    return run;
  }

  query(): Promise<{ held: { name: string }[] }> {
    return Promise.resolve({ held: [...this.#held.keys()].map((name) => ({ name })) });
  }

  /** Forgets every name, as closing every document of an origin would. */
  reset(): void {
    this.#held.clear();
  }
}

const locks = new FakeLockManager();

/** Lets queued channel deliveries and the store's own awaits run. */
const settle = async () => {
  for (let turn = 0; turn < 25; turn++) await new Promise((resolve) => setTimeout(resolve, 0));
};

const open = () => new SharedMemoryCredentialStorage({ name: 'test-credentials' });

let stores: SharedMemoryCredentialStorage[] = [];
const track = (store: SharedMemoryCredentialStorage) => {
  stores.push(store);
  return store;
};

beforeEach(() => {
  locks.reset();
  vi.stubGlobal('navigator', { locks });
});

afterEach(() => {
  for (const store of stores) store.close();
  stores = [];
  vi.unstubAllGlobals();
});

describe('SharedMemoryCredentialStorage', () => {
  it('reports what it is: shared between tabs, and not durable', () => {
    const storage = track(open());
    expect(storage.shared).toBe(true);
    expect(storage.durable).toBe(false);
  });

  it('holds a key and hands it back as it was given', async () => {
    const storage = track(open());
    const identity = await storage.create();

    await storage.set(SLOTS.session, { identity });

    const stored = await storage.get(SLOTS.session);
    // The same object, not a round trip: it is what lets a non-extractable key be
    // held at all.
    expect(stored?.identity).toBe(identity);
  });

  it('reports nothing for a slot never written', async () => {
    const storage = track(open());
    expect(await storage.get(SLOTS.app)).toBeNull();
  });

  it('replicates a write to a peer that is already running', async () => {
    const first = track(open());
    const second = track(open());
    await settle();

    const identity = await first.create();
    const chain = await DelegationChain.create(
      identity,
      Ed25519KeyIdentity.generate().getPublicKey(),
      new Date(Date.now() + 60_000),
    );
    await first.set(SLOTS.app, { identity, chain });
    await settle();

    const stored = await second.get(SLOTS.app);
    expect(stored).not.toBeNull();
    // Reconstructed from the handle and the chain's JSON, so it signs for the
    // same key without key material having crossed.
    expect(stored?.identity.getPublicKey().toDer()).toEqual(identity.getPublicKey().toDer());
    expect(stored?.chain?.delegations).toHaveLength(1);
  });

  it('replicates a removal', async () => {
    const first = track(open());
    const second = track(open());
    await settle();

    const identity = await first.create();
    await first.set(SLOTS.session, { identity });
    await settle();
    expect(await second.get(SLOTS.session)).not.toBeNull();

    await first.remove(SLOTS.session);
    await settle();

    expect(await second.get(SLOTS.session)).toBeNull();
  });

  it('starts cold and reads what a peer already held', async () => {
    const first = track(open());
    const identity = await first.create();
    await first.set(SLOTS.sessionPending, { identity });
    await settle();

    // Constructed after the write, so nothing was broadcast to it: what it reads
    // can only have come from asking.
    const second = track(open());

    const stored = await second.get(SLOTS.sessionPending);
    expect(stored?.identity.getPublicKey().toDer()).toEqual(identity.getPublicKey().toDer());
  });

  it('does not wait when there is no peer to wait for', async () => {
    const first = track(open());
    await settle();
    first.close();
    locks.reset();

    // Nothing holds a presence lock, so a read has nothing to wait on and must
    // answer rather than hanging until something times out.
    const alone = track(open());
    await expect(alone.get(SLOTS.session)).resolves.toBeNull();
  });

  it('stops waiting when the peer it was waiting for goes away', async () => {
    const first = track(open());
    await settle();

    // A peer holding a presence lock but never answering: it is gone before the
    // ask reaches it. The wait ends on its lock being released, not on a clock.
    first.close();
    locks.reset();

    const second = track(open());
    await expect(second.get(SLOTS.session)).resolves.toBeNull();
  });

  it('keeps its own write when an answer describes an older moment', async () => {
    // No peer, so nothing is asked and no answer is in flight: the offer below is
    // posted deliberately. Racing a real peer would make the scheduler decide
    // which write lands first, which is not what this is about.
    const storage = track(open());
    const mine = await storage.create();
    await storage.set(SLOTS.session, { identity: mine });

    const older = await storage.create();
    const peer = new BroadcastChannel('test-credentials');
    peer.postMessage({
      kind: 'offer',
      entries: [{ slot: SLOTS.session, keyPair: older.getKeyPair() }],
    });
    await settle();
    peer.close();

    // An answer fills gaps. It never replaces a write made since the question,
    // because the answer describes a moment already past.
    expect((await storage.get(SLOTS.session))?.identity).toBe(mine);
  });

  it('carries a key as a handle that cannot be exported', async () => {
    const first = track(open());
    const second = track(open());
    await settle();

    const identity = await first.create();
    await first.set(SLOTS.session, { identity });
    await settle();

    const stored = await second.get(SLOTS.session);
    // What crosses is a handle, not key material: the peer can sign with it and
    // nothing can read the private half back out.
    expect(stored?.identity.getKeyPair().privateKey.extractable).toBe(false);
    await expect(
      crypto.subtle.exportKey('pkcs8', stored?.identity.getKeyPair().privateKey as CryptoKey),
    ).rejects.toThrow();
  });

  it('ignores a message that is not one of its own', async () => {
    const storage = track(open());
    await settle();

    // The channel reaches one origin, so a stranger on the name is our own code
    // through a deploy, or an application posting on it. Neither may throw here
    // or leave a slot holding something unusable.
    const intruder = new BroadcastChannel('test-credentials');
    intruder.postMessage({ kind: 'put', slot: SLOTS.session });
    intruder.postMessage('not an object');
    intruder.postMessage({ kind: 'nonsense', slot: SLOTS.session });
    await settle();
    intruder.close();

    expect(await storage.get(SLOTS.session)).toBeNull();
  });

  it('takes nothing in once closed', async () => {
    const first = track(open());
    const second = track(open());
    await settle();

    second.close();
    const identity = await first.create();
    await first.set(SLOTS.app, { identity });
    await settle();

    // Closing stops the replication as well as letting go of the name, so a
    // closed instance does not go on collecting credentials it will never use.
    expect(await second.get(SLOTS.app)).toBeNull();
  });

  it('keeps two names apart', async () => {
    const mine = track(new SharedMemoryCredentialStorage({ name: 'one' }));
    const theirs = track(new SharedMemoryCredentialStorage({ name: 'two' }));
    await settle();

    const identity = await mine.create();
    await mine.set(SLOTS.session, { identity });
    await settle();

    expect(await theirs.get(SLOTS.session)).toBeNull();
  });

  it('starts alone where the environment has no locks', async () => {
    vi.stubGlobal('navigator', {});
    const storage = track(open());
    // Nothing can be enumerated, so waiting could only cost a load. Answering is
    // what keeps coordination able to suppress a mint without being required for
    // one.
    await expect(storage.get(SLOTS.session)).resolves.toBeNull();
  });
});
