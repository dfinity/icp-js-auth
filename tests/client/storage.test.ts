import { beforeEach, describe, expect, it, vi } from 'vitest';
import { IdbKeyVal } from '../../src/client/db.ts';
import { IdbStorage } from '../../src/client/storage.ts';

let testCounter = 0;

const testStorage = () =>
  new IdbStorage({
    dbName: `storage-db-${testCounter}`,
    storeName: `storage-store-${testCounter}`,
  });

beforeEach(() => {
  testCounter += 1;
  vi.restoreAllMocks();
});

describe('IdbStorage', () => {
  it('should share a single IdbKeyVal across concurrent first accesses', async () => {
    const createSpy = vi.spyOn(IdbKeyVal, 'create');
    const storage = testStorage();

    await Promise.all([
      storage.set('a', '1'),
      storage.get('a'),
      storage.set('b', '2'),
      storage.remove('c'),
    ]);

    expect(createSpy).toHaveBeenCalledTimes(1);
    expect(await storage.get('a')).toBe('1');
    expect(await storage.get('b')).toBe('2');
  });

  it('should not cache a failed database open', async () => {
    const createSpy = vi.spyOn(IdbKeyVal, 'create').mockRejectedValueOnce(new Error('open failed'));
    const storage = testStorage();

    await expect(storage.get('a')).rejects.toThrow('open failed');

    await storage.set('a', '1');
    expect(await storage.get('a')).toBe('1');
    expect(createSpy).toHaveBeenCalledTimes(2);
  });
});
