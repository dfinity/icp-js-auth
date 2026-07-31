import type { IDBPDatabase } from 'idb';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { IdbKeyVal } from '../../src/client/db.ts';

// Wrap `openDB` to capture every connection the module opens, so tests can
// close one out from under IdbKeyVal the way a browser force-close does.
const opened = vi.hoisted(() => ({ dbs: [] as IDBPDatabase<unknown>[] }));

vi.mock('idb', async (importOriginal) => {
  const actual = await importOriginal<typeof import('idb')>();
  const openDB = (async (
    ...args: Parameters<typeof actual.openDB>
  ): Promise<IDBPDatabase<unknown>> => {
    const db = await actual.openDB(...args);
    opened.dbs.push(db);
    return db;
  }) as typeof actual.openDB;
  return { ...actual, openDB };
});

let testCounter = 0;

const testDb = async () => {
  return await IdbKeyVal.create({
    dbName: `recovery-db-${testCounter}`,
    storeName: `recovery-store-${testCounter}`,
  });
};

beforeEach(() => {
  testCounter += 1;
  opened.dbs.length = 0;
});

describe('IdbKeyVal connection recovery', () => {
  it('should reopen and retry when the cached connection is closed', async () => {
    const db = await testDb();
    await db.set('testKey', 'before');
    expect(opened.dbs.length).toBe(1);

    // Simulate the browser force-closing the connection without the
    // `terminated` event having fired yet.
    opened.dbs[0].close();

    expect(await db.get('testKey')).toBe('before');
    await db.set('testKey', 'after');
    expect(await db.get('testKey')).toBe('after');
    expect(opened.dbs.length).toBe(2);
  });

  it('should recover a write issued after the connection was closed', async () => {
    const db = await testDb();
    opened.dbs[0].close();

    await db.set('testKey', 'testValue');
    expect(await db.get('testKey')).toBe('testValue');
    expect(opened.dbs.length).toBe(2);
  });
});
