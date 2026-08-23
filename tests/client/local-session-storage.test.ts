import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { LocalSessionStorage } from '../../src/client/local-session-storage.ts';

async function testChain(): Promise<DelegationChain> {
  const key = Ed25519KeyIdentity.generate();
  return DelegationChain.create(key, key.getPublicKey(), new Date(Date.now() + 3.6e6));
}

beforeEach(() => localStorage.clear());

describe('LocalSessionStorage', () => {
  it('discard removes the session, since nothing here is shared', async () => {
    const storage = new LocalSessionStorage();
    storage.set({ chain: await testChain() });

    storage.discard();

    expect(storage.get()).toBeNull();
  });

  it('returns null when nothing is stored', () => {
    expect(new LocalSessionStorage().get()).toBeNull();
  });

  it('round-trips a delegation chain', async () => {
    const storage = new LocalSessionStorage();
    const chain = await testChain();

    storage.set({ chain: chain });
    const restored = storage.get();

    expect(restored).not.toBeNull();
    expect(restored?.chain.toJSON()).toEqual(chain.toJSON());
  });

  it('writes under the configured key', async () => {
    const storage = new LocalSessionStorage();
    storage.set({ chain: await testChain() });
    expect(localStorage.getItem(new LocalSessionStorage().key)).not.toBeNull();
  });

  it('removes the stored delegation', async () => {
    const storage = new LocalSessionStorage();
    storage.set({ chain: await testChain() });

    storage.remove();

    expect(storage.get()).toBeNull();
  });

  it('returns null for a corrupt stored value', () => {
    localStorage.setItem(new LocalSessionStorage().key, 'not json');
    expect(new LocalSessionStorage().get()).toBeNull();
  });

  it('notifies on a same-tab set and remove', async () => {
    const storage = new LocalSessionStorage();
    const listener = vi.fn();
    storage.subscribe(listener);

    storage.set({ chain: await testChain() });
    expect(listener).toHaveBeenCalledTimes(1);

    storage.remove();
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it('notifies on a cross-tab write (storage event)', async () => {
    const storage = new LocalSessionStorage();
    const listener = vi.fn();
    storage.subscribe(listener);

    // Another tab wrote the delegation; the value changed and the `storage`
    // event carries it here.
    localStorage.setItem(storage.key, JSON.stringify((await testChain()).toJSON()));
    globalThis.dispatchEvent(
      new StorageEvent('storage', { key: storage.key, storageArea: localStorage }),
    );

    expect(listener).toHaveBeenCalledOnce();
  });

  it('notifies when the whole store is cleared (null key)', async () => {
    const storage = new LocalSessionStorage();
    storage.set({ chain: await testChain() });
    const listener = vi.fn();
    storage.subscribe(listener);

    localStorage.clear();
    globalThis.dispatchEvent(new StorageEvent('storage', { key: null, storageArea: localStorage }));

    expect(listener).toHaveBeenCalledOnce();
  });

  it('does not notify when a storage event reflects no change', () => {
    const storage = new LocalSessionStorage();
    const listener = vi.fn();
    storage.subscribe(listener);

    // Same key and area, but the stored value didn't actually change.
    globalThis.dispatchEvent(
      new StorageEvent('storage', { key: storage.key, storageArea: localStorage }),
    );

    expect(listener).not.toHaveBeenCalled();
  });

  it('ignores storage events for unrelated keys', () => {
    const storage = new LocalSessionStorage();
    const listener = vi.fn();
    storage.subscribe(listener);

    globalThis.dispatchEvent(
      new StorageEvent('storage', { key: 'something-else', storageArea: localStorage }),
    );

    expect(listener).not.toHaveBeenCalled();
  });

  it('ignores storage events from another storage area (e.g. sessionStorage)', () => {
    const storage = new LocalSessionStorage();
    const listener = vi.fn();
    storage.subscribe(listener);

    // Same key, but a different Storage area — must not notify.
    globalThis.dispatchEvent(
      new StorageEvent('storage', { key: storage.key, storageArea: sessionStorage }),
    );

    expect(listener).not.toHaveBeenCalled();
  });

  it('stops notifying after unsubscribe', () => {
    const storage = new LocalSessionStorage();
    const listener = vi.fn();
    const unsubscribe = storage.subscribe(listener);

    unsubscribe();
    globalThis.dispatchEvent(
      new StorageEvent('storage', { key: storage.key, storageArea: localStorage }),
    );

    expect(listener).not.toHaveBeenCalled();
  });
});
