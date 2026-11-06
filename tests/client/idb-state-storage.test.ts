import { Principal } from '@icp-sdk/core/principal';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { IdbKeyVal } from '../../src/client/db.ts';
import { IdbStateStorage } from '../../src/client/idb-state-storage.ts';
import { LocalStateStorage } from '../../src/client/state-storage.ts';

const alice = {
  principal: Principal.selfAuthenticating(new Uint8Array([1, 2, 3])),
  expiration: BigInt('1893456000000000000'),
};
const bob = {
  principal: Principal.selfAuthenticating(new Uint8Array([4, 5, 6])),
  expiration: BigInt('1893456000000000001'),
};

// IndexedDB lives for the whole file, so each test writes under its own key.
let counter = 0;
const freshKey = () => `state-${++counter}`;

/** Lets channel deliveries and IndexedDB transactions run. */
const settle = async () => {
  for (let turn = 0; turn < 25; turn++) await new Promise((resolve) => setTimeout(resolve, 0));
};

let stores: IdbStateStorage[] = [];
const track = (store: IdbStateStorage) => {
  stores.push(store);
  return store;
};

/** A store as a tab opens it: `localStorage` is there. */
const openTab = () => track(new IdbStateStorage());

/** A store as a worker opens it: no `localStorage`. */
const openWorker = () => {
  vi.stubGlobal('localStorage', undefined);
  try {
    return track(new IdbStateStorage());
  } finally {
    vi.unstubAllGlobals();
  }
};

afterEach(() => {
  for (const store of stores) store.close();
  stores = [];
  localStorage.clear();
});

describe('IdbStateStorage in a tab', () => {
  it('reads a sign-in that LocalStateStorage wrote, so an upgrade keeps users signed in', () => {
    const key = freshKey();
    new LocalStateStorage().set(key, alice);

    expect(openTab().get(key)).toEqual({ ...alice, held: true });
  });

  it('writes what LocalStateStorage reads', () => {
    const key = freshKey();
    openTab().set(key, alice);

    expect(new LocalStateStorage().get(key)).toEqual({ ...alice, held: true });
  });

  it('is ready straight away', async () => {
    await expect(openTab().ready()).resolves.toBeUndefined();
  });
});

describe('IdbStateStorage in a worker', () => {
  it('loads what a tab wrote', async () => {
    const key = freshKey();
    openTab().set(key, alice);
    await settle();

    const worker = openWorker();
    await worker.ready();

    expect(worker.get(key)).toEqual({ ...alice, held: true });
  });

  it('is told when a tab signs in and out', async () => {
    const key = freshKey();
    const tab = openTab();
    const worker = openWorker();
    await worker.ready();
    const listener = vi.fn();
    worker.subscribe(key, listener);

    tab.set(key, alice);
    await settle();
    expect(worker.get(key)).toEqual({ ...alice, held: true });
    expect(listener).toHaveBeenCalledTimes(1);

    tab.remove(key);
    await settle();
    expect(worker.get(key)).toBeNull();
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it('follows an account switch in a tab', async () => {
    const key = freshKey();
    const tab = openTab();
    tab.set(key, alice);
    await settle();
    const worker = openWorker();
    await worker.ready();

    tab.set(key, bob);
    await settle();

    expect(worker.get(key)).toEqual({ ...bob, held: true });
  });

  it('tells tabs when it signs out', async () => {
    const key = freshKey();
    const tab = openTab();
    tab.set(key, alice);
    await settle();
    const worker = openWorker();
    await worker.ready();
    const listener = vi.fn();
    tab.subscribe(key, listener);

    worker.remove(key);
    await settle();

    expect(tab.get(key)).toBeNull();
    expect(localStorage.getItem(key)).toBeNull();
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('starts signed out where there is no IndexedDB', async () => {
    vi.stubGlobal('indexedDB', undefined);
    try {
      const worker = openWorker();
      await worker.ready();
      expect(worker.get(freshKey())).toBeNull();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe('IdbStateStorage after an upgrade from LocalStateStorage', () => {
  it('copies the existing sign-in for workers the first time a tab reads it', async () => {
    const key = freshKey();
    new LocalStateStorage().set(key, alice);

    openTab().get(key);
    await settle();

    const worker = openWorker();
    await worker.ready();
    expect(worker.get(key)).toEqual({ ...alice, held: true });
  });

  it('does not copy over a sign-out IndexedDB already has', async () => {
    const key = freshKey();
    const worker = openWorker();
    await worker.ready();
    worker.remove(key);
    await settle();

    // A tab still holding the record from before the sign-out reached it.
    new LocalStateStorage().set(key, alice);
    openTab().get(key);
    await settle();

    const db = await IdbKeyVal.create({ dbName: 'auth-client-state-db', storeName: 'ic-state' });
    expect(await db.get(key)).toEqual({ raw: null });
    const later = openWorker();
    await later.ready();
    expect(later.get(key)).toBeNull();
  });
});
