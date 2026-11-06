import { Principal } from '@icp-sdk/core/principal';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { IdbKeyVal } from '../../src/client/db.ts';
import { LocalStateStorage } from '../../src/client/local-state-storage.ts';
import { formatState } from '../../src/client/state-storage.ts';

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

const stateDb = () => IdbKeyVal.create({ dbName: 'auth-client-state-db', storeName: 'ic-keyval' });

type Written = typeof alice | null;

/** Waits until IndexedDB holds `state` under `key`, which is when other stores can read it. */
const committed = async (key: string, state: Written) => {
  const db = await stateDb();
  const raw = state === null ? null : formatState(state);
  await vi.waitFor(async () => expect(await db.get(key)).toEqual({ raw }));
};

let stores: LocalStateStorage[] = [];
let listening: (() => void)[] = [];
// A store follows other tabs and workers while it has a subscriber, as it does
// under a client, so every store here gets one.
const track = (store: LocalStateStorage) => {
  stores.push(store);
  listening.push(store.subscribe('listening', () => {}));
  return store;
};

/** A store as a tab opens it: `localStorage` is there. */
const openTab = () => track(new LocalStateStorage());

/** A store as a worker opens it: no `localStorage`. */
const openWorker = () => {
  vi.stubGlobal('localStorage', undefined);
  try {
    return track(new LocalStateStorage());
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

describe('LocalStateStorage in a tab', () => {
  it('reads a sign-in an earlier version wrote, so an upgrade keeps users signed in', () => {
    const key = freshKey();
    localStorage.setItem(key, formatState(alice));

    expect(openTab().get(key)).toEqual({ ...alice, held: true });
  });

  it('writes what an earlier version reads', () => {
    const key = freshKey();
    openTab().set(key, alice);

    expect(localStorage.getItem(key)).toBe(formatState(alice));
  });

  it('is ready straight away', async () => {
    await expect(openTab().ready()).resolves.toBeUndefined();
  });
});

describe('LocalStateStorage in a worker', () => {
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

  it('only reads: signing in and out happens in a page', () => {
    const key = freshKey();
    const worker = openWorker();

    expect(worker.isReadOnly).toBe(true);
    expect(() => worker.set(key, alice)).toThrow(/read-only/);
    expect(() => worker.remove(key)).toThrow(/read-only/);
    expect(() => worker.discard(key)).toThrow(/read-only/);
    expect(openTab().isReadOnly).toBe(false);
  });

  it('starts signed out where there is no IndexedDB', async () => {
    const key = freshKey();
    openTab().set(key, alice);
    await committed(key, alice);

    // Both hidden through the read, which is when the store opens IndexedDB.
    vi.stubGlobal('localStorage', undefined);
    vi.stubGlobal('indexedDB', undefined);
    try {
      const worker = new LocalStateStorage();
      worker.get(key);
      await worker.ready();
      expect(worker.get(key)).toBeNull();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe('LocalStateStorage after an upgrade from an earlier version', () => {
  it('copies the existing sign-in for workers the first time a tab reads it', async () => {
    const key = freshKey();
    localStorage.setItem(key, formatState(alice));

    openTab().get(key);
    await committed(key, alice);

    const worker = openWorker();
    worker.get(key);
    await worker.ready();
    expect(worker.get(key)).toEqual({ ...alice, held: true });
  });

  it('mirrors what localStorage holds over an older mirror', async () => {
    const key = freshKey();
    openTab().set(key, bob);
    await committed(key, bob);

    // A write that never reached the mirror: a page closed first, or a tab still
    // on the earlier version wrote only `localStorage`.
    localStorage.setItem(key, formatState(alice));
    const tab = openTab();

    expect(tab.get(key)).toEqual({ ...alice, held: true });
    await committed(key, alice);
    expect(tab.get(key)).toEqual({ ...alice, held: true });
    const worker = openWorker();
    worker.get(key);
    await worker.ready();
    expect(worker.get(key)).toEqual({ ...alice, held: true });
  });
});

describe('LocalStateStorage ordering', () => {
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

  it('tells every other store in a tab when one signs out', async () => {
    const key = freshKey();
    const one = openTab();
    const two = openTab();
    const three = openTab();
    one.set(key, alice);
    await committed(key, alice);
    const first = vi.fn();
    const second = vi.fn();
    one.subscribe(key, first);
    two.subscribe(key, second);

    // `storage` does not fire in the tab that wrote, so the other stores here
    // hear it through the announcement.
    three.remove(key);

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

describe('LocalStateStorage listening', () => {
  it('stops following other contexts once its last subscriber leaves', async () => {
    const key = freshKey();
    const tab = openTab();
    // Not through openWorker(), which subscribes for the whole test.
    vi.stubGlobal('localStorage', undefined);
    const worker = new LocalStateStorage();
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

  it('reloads what it holds when it is subscribed to again', async () => {
    const key = freshKey();
    const tab = openTab();
    tab.set(key, alice);
    await committed(key, alice);
    vi.stubGlobal('localStorage', undefined);
    const worker = new LocalStateStorage();
    vi.unstubAllGlobals();
    const stop = worker.subscribe(key, () => {});
    worker.get(key);
    await worker.ready();
    expect(worker.get(key)).toEqual({ ...alice, held: true });

    // Changed while nobody was subscribed, so nothing followed it.
    stop();
    tab.set(key, bob);
    await committed(key, bob);
    await settle();
    expect(worker.get(key)).toEqual({ ...alice, held: true });

    listening.push(worker.subscribe(key, () => {}));
    await worker.ready();

    expect(worker.get(key)).toEqual({ ...bob, held: true });
  });
});
