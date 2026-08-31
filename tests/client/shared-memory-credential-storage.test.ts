import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APP_SLOT, PENDING_SLOT, SESSION_SLOT } from '../../src/client/credential-storage.ts';
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

    await storage.set(SESSION_SLOT, { identity });

    const stored = await storage.get(SESSION_SLOT);
    // The same object, not a round trip: it is what lets a non-extractable key be
    // held at all.
    expect(stored?.identity).toBe(identity);
  });

  it('reports nothing for a slot never written', async () => {
    const storage = track(open());
    expect(await storage.get(APP_SLOT)).toBeNull();
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
    await first.set(APP_SLOT, { identity, chain });
    await settle();

    const stored = await second.get(APP_SLOT);
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
    await first.set(SESSION_SLOT, { identity });
    await settle();
    expect(await second.get(SESSION_SLOT)).not.toBeNull();

    await first.remove(SESSION_SLOT);
    await settle();

    expect(await second.get(SESSION_SLOT)).toBeNull();
  });

  it('starts cold and reads what a peer already held', async () => {
    const first = track(open());
    const identity = await first.create();
    await first.set(PENDING_SLOT, { identity });
    await settle();

    // Constructed after the write, so nothing was broadcast to it: what it reads
    // can only have come from asking.
    const second = track(open());

    const stored = await second.get(PENDING_SLOT);
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
    await expect(alone.get(SESSION_SLOT)).resolves.toBeNull();
  });

  it('stops waiting when the peer it was waiting for goes away', async () => {
    const first = track(open());
    await settle();

    // A peer holding a presence lock but never answering: it is gone before the
    // ask reaches it. The wait ends on its lock being released, not on a clock.
    first.close();
    locks.reset();

    const second = track(open());
    await expect(second.get(SESSION_SLOT)).resolves.toBeNull();
  });

  it('keeps its own write when a peer answers an older question', async () => {
    const first = track(open());
    const theirs = await first.create();
    await first.set(SESSION_SLOT, { identity: theirs });
    await settle();

    const second = track(open());
    const mine = await second.create();
    // Written before the answer to the ask arrives, so the answer describes a
    // moment already past and must not replace it.
    await second.set(SESSION_SLOT, { identity: mine });
    await settle();

    const stored = await second.get(SESSION_SLOT);
    expect(stored?.identity).toBe(mine);
  });

  it('keeps two names apart', async () => {
    const mine = track(new SharedMemoryCredentialStorage({ name: 'one' }));
    const theirs = track(new SharedMemoryCredentialStorage({ name: 'two' }));
    await settle();

    const identity = await mine.create();
    await mine.set(SESSION_SLOT, { identity });
    await settle();

    expect(await theirs.get(SESSION_SLOT)).toBeNull();
  });

  it('starts alone where the environment has no locks', async () => {
    vi.stubGlobal('navigator', {});
    const storage = track(open());
    // Nothing can be enumerated, so waiting could only cost a load. Answering is
    // what keeps coordination able to suppress a mint without being required for
    // one.
    await expect(storage.get(SESSION_SLOT)).resolves.toBeNull();
  });
});
