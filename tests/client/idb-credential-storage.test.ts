import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SESSION_SLOT } from '../../src/client/credential-storage.ts';
import { IdbKeyVal } from '../../src/client/db.ts';
import { IdbCredentialStorage } from '../../src/client/idb-credential-storage.ts';

let testCounter = 0;

const testStorage = () =>
  new IdbCredentialStorage({
    dbName: `storage-db-${testCounter}`,
    storeName: `storage-store-${testCounter}`,
  });

const testChain = async () => {
  const key = Ed25519KeyIdentity.generate();
  return DelegationChain.create(key, key.getPublicKey(), new Date(Date.now() + 3.6e6));
};

beforeEach(() => {
  testCounter += 1;
  vi.restoreAllMocks();
});

describe('IdbCredentialStorage', () => {
  it('reports what it is: shared between tabs, and durable', () => {
    const storage = testStorage();

    expect(storage.shared).toBe(true);
    expect(storage.durable).toBe(true);
  });

  it('stores a key and its delegation as one record', async () => {
    const storage = testStorage();
    const identity = await storage.create();
    const chain = await testChain();

    await storage.set(SESSION_SLOT, { identity, chain });

    const stored = await storage.get(SESSION_SLOT);
    expect(stored?.identity.getPublicKey().toDer()).toEqual(identity.getPublicKey().toDer());
    expect(stored?.chain?.toJSON()).toEqual(chain.toJSON());
  });

  it('stores a key with no delegation, which is what a ceremony in flight holds', async () => {
    const storage = testStorage();
    const identity = await storage.create();

    await storage.set('pending', { identity });

    const stored = await storage.get('pending');
    expect(stored?.identity.getPublicKey().toDer()).toEqual(identity.getPublicKey().toDer());
    expect(stored?.chain).toBeUndefined();
  });

  it('generates a key whose private half cannot be read back', async () => {
    const identity = await testStorage().create();

    expect(identity.getKeyPair().privateKey.extractable).toBe(false);
  });

  it('reports nothing stored rather than throwing on a record it cannot read', async () => {
    const storage = testStorage();
    const identity = await storage.create();
    await storage.set(SESSION_SLOT, { identity, chain: await testChain() });

    const db = await IdbKeyVal.create({
      dbName: `storage-db-${testCounter}`,
      storeName: `storage-store-${testCounter}`,
    });
    await db.set(SESSION_SLOT, { keyPair: identity.getKeyPair(), chain: 'not a chain' });

    expect(await storage.get(SESSION_SLOT)).toBeNull();
  });

  it('should share a single IdbKeyVal across concurrent first accesses', async () => {
    const createSpy = vi.spyOn(IdbKeyVal, 'create');
    const storage = testStorage();
    const identity = await storage.create();
    const chain = await testChain();

    await Promise.all([
      storage.set('a', { identity, chain }),
      storage.get('a'),
      storage.set('b', { identity, chain }),
      storage.remove('c'),
    ]);

    expect(createSpy).toHaveBeenCalledTimes(1);
    expect(await storage.get('a')).not.toBeNull();
    expect(await storage.get('b')).not.toBeNull();
  });

  it('should not cache a failed database open', async () => {
    const createSpy = vi.spyOn(IdbKeyVal, 'create').mockRejectedValueOnce(new Error('open failed'));
    const storage = testStorage();

    await expect(storage.get('a')).rejects.toThrow('open failed');

    await storage.remove('a');
    expect(createSpy).toHaveBeenCalledTimes(2);
  });
});
