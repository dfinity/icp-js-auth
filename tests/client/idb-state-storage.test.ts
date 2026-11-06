import { Principal } from '@icp-sdk/core/principal';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { IdbKeyVal } from '../../src/client/db.ts';
import { IdbStateStorage } from '../../src/client/idb-state-storage.ts';
import { formatState, LocalStateStorage } from '../../src/client/state-storage.ts';

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

const stateDb = () => IdbKeyVal.create({ dbName: 'auth-client-state-db', storeName: 'ic-state' });

type Written = typeof alice | null;

/** Waits until IndexedDB holds `state` under `key`, which is when other stores can read it. */
const committed = async (key: string, state: Written) => {
  const db = await stateDb();
  const raw = state === null ? null : formatState(state);
  await vi.waitFor(async () => expect(await db.get(key)).toEqual({ raw }));
};

let stores: IdbStateStorage[] = [];
let listening: (() => void)[] = [];
// A store follows other tabs and workers while it has a subscriber, as it does
// under a client, so every store here gets one.
const track = (store: IdbStateStorage) => {
  stores.push(store);
  listening.push(store.subscribe('listening', () => {}));
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
  for (const stop of listening) stop();
  listening = [];
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
    await committed(key, alice);

    const worker = openWorker();
    worker.get(key);
    await worker.ready();

    expect(worker.get(key)).toEqual({ ...alice, held: true });
  });

  it('is told when a tab signs in and out', async () => {
    const key = freshKey();
    const tab = openTab();
    const worker = openWorker();
    worker.get(key);
    await worker.ready();
    const listener = vi.fn();
    worker.subscribe(key, listener);

    tab.set(key, alice);
    await vi.waitFor(() => expect(worker.get(key)).toEqual({ ...alice, held: true }));
    expect(listener).toHaveBeenCalledTimes(1);

    tab.remove(key);
    await vi.waitFor(() => expect(worker.get(key)).toBeNull());
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it('follows an account switch in a tab', async () => {
    const key = freshKey();
    const tab = openTab();
    tab.set(key, alice);
    await committed(key, alice);
    const worker = openWorker();
    worker.get(key);
    await worker.ready();

    tab.set(key, bob);

    await vi.waitFor(() => expect(worker.get(key)).toEqual({ ...bob, held: true }));
  });

  it('tells tabs when it signs out', async () => {
    const key = freshKey();
    const tab = openTab();
    tab.set(key, alice);
    await committed(key, alice);
    const worker = openWorker();
    worker.get(key);
    await worker.ready();
    const listener = vi.fn();
    tab.subscribe(key, listener);

    worker.remove(key);

    await vi.waitFor(() => expect(tab.get(key)).toBeNull());
    expect(localStorage.getItem(key)).toBeNull();
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('starts signed out where there is no IndexedDB', async () => {
    vi.stubGlobal('indexedDB', undefined);
    try {
      const key = freshKey();
      const worker = openWorker();
      worker.get(key);
      await worker.ready();
      expect(worker.get(key)).toBeNull();
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
    await committed(key, alice);

    const worker = openWorker();
    worker.get(key);
    await worker.ready();
    expect(worker.get(key)).toEqual({ ...alice, held: true });
  });

  it('does not copy over a sign-out IndexedDB already has', async () => {
    const key = freshKey();
    const worker = openWorker();
    worker.get(key);
    await worker.ready();
    worker.remove(key);
    await committed(key, null);

    // A tab still holding the record from before the sign-out reached it.
    new LocalStateStorage().set(key, alice);
    const tab = openTab();
    tab.get(key);

    // The tab takes the sign-out rather than keeping its stale record.
    await vi.waitFor(() => expect(tab.get(key)).toBeNull());
    await settle();
    expect(await (await stateDb()).get(key)).toEqual({ raw: null });
    const later = openWorker();
    later.get(key);
    await later.ready();
    expect(later.get(key)).toBeNull();
  });
});

describe('IdbStateStorage ordering', () => {
  it('lands a write a subscriber makes after the write that notified it', async () => {
    const key = freshKey();
    const tab = openTab();
    tab.subscribe(key, () => {
      if (tab.get(key) !== null) tab.remove(key);
    });

    tab.set(key, alice);
    await committed(key, null);

    expect(tab.get(key)).toBeNull();
    const worker = openWorker();
    worker.get(key);
    await worker.ready();
    expect(worker.get(key)).toBeNull();
  });

  it('tells every store in a tab when a worker signs out', async () => {
    const key = freshKey();
    const one = openTab();
    const two = openTab();
    one.set(key, alice);
    await committed(key, alice);
    const worker = openWorker();
    worker.get(key);
    await worker.ready();
    const first = vi.fn();
    const second = vi.fn();
    one.subscribe(key, first);
    two.subscribe(key, second);

    worker.remove(key);

    await vi.waitFor(() => expect(second).toHaveBeenCalledTimes(1));
    await vi.waitFor(() => expect(first).toHaveBeenCalledTimes(1));
  });

  it('resolves ready only once the keys read so far have loaded', async () => {
    const key = freshKey();
    openTab().set(key, alice);
    await committed(key, alice);

    // Holds the worker's read of IndexedDB until released.
    let release = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const get = IdbKeyVal.prototype.get;
    const getSpy = vi.spyOn(IdbKeyVal.prototype, 'get').mockImplementation(async function (
      this: IdbKeyVal,
      slot,
    ) {
      if (slot === key) await held;
      return get.call(this, slot);
    });
    try {
      const worker = openWorker();
      expect(worker.get(key)).toBeNull();

      let isReady = false;
      void worker.ready().then(() => {
        isReady = true;
      });
      await settle();
      expect(isReady).toBe(false);

      release();
      await worker.ready();
      expect(worker.get(key)).toEqual({ ...alice, held: true });
    } finally {
      getSpy.mockRestore();
    }
  });
});

describe('IdbStateStorage listening', () => {
  it('stops following other contexts once its last subscriber leaves', async () => {
    const key = freshKey();
    const tab = openTab();
    // Not through openWorker(), which subscribes for the whole test.
    vi.stubGlobal('localStorage', undefined);
    const worker = new IdbStateStorage();
    vi.unstubAllGlobals();
    const stopOne = worker.subscribe(key, () => {});
    const stopTwo = worker.subscribe(key, () => {});
    worker.get(key);
    await worker.ready();

    stopOne();
    tab.set(key, alice);
    await vi.waitFor(() => expect(worker.get(key)).toEqual({ ...alice, held: true }));

    stopTwo();
    tab.set(key, bob);
    await committed(key, bob);
    await settle();

    expect(worker.get(key)).toEqual({ ...alice, held: true });
  });
});
