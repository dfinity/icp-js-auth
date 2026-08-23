import { beforeEach, describe, expect, it, vi } from 'vitest';
import { IdbKeyVal } from '../../src/client/db.ts';
import { IdbIdentityStorage } from '../../src/client/idb-identity-storage.ts';

let testCounter = 0;

const testStorage = () =>
  new IdbIdentityStorage({
    dbName: `storage-db-${testCounter}`,
    storeName: `storage-store-${testCounter}`,
  });

beforeEach(() => {
  testCounter += 1;
  vi.restoreAllMocks();
});

describe('IdbIdentityStorage', () => {
  it('create() mints an identity without persisting it', async () => {
    const storage = testStorage();

    await storage.create();

    expect(await storage.get()).toBeNull();
  });

  it('persists and restores the same ECDSA identity via set()', async () => {
    const storage = testStorage();

    const created = await storage.create();
    await storage.set(created);
    const restored = await storage.get();

    expect(restored).not.toBeNull();
    expect(restored?.getPrincipal().toText()).toBe(created.getPrincipal().toText());
  });

  it('returns null when nothing is stored', async () => {
    expect(await testStorage().get()).toBeNull();
  });

  it('removes the stored identity', async () => {
    const storage = testStorage();
    await storage.set(await storage.create());

    await storage.remove();

    expect(await storage.get()).toBeNull();
  });

  it('should share a single IdbKeyVal across concurrent first accesses', async () => {
    const createSpy = vi.spyOn(IdbKeyVal, 'create');
    const storage = testStorage();

    const identity = await storage.create();
    await Promise.all([storage.set(identity), storage.get(), storage.remove()]);

    expect(createSpy).toHaveBeenCalledTimes(1);
  });

  it('should not cache a failed database open', async () => {
    const createSpy = vi.spyOn(IdbKeyVal, 'create').mockRejectedValueOnce(new Error('open failed'));
    const storage = testStorage();

    await expect(storage.get()).rejects.toThrow('open failed');

    const created = await storage.create();
    await storage.set(created);
    expect((await storage.get())?.getPrincipal().toText()).toBe(created.getPrincipal().toText());
    expect(createSpy).toHaveBeenCalledTimes(2);
  });
});
