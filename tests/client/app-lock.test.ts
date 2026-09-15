import { afterEach, describe, expect, it, vi } from 'vitest';
import { stealLock, stealMintLock, withMintLock } from '../../src/client/app-lock.ts';

/**
 * jsdom has no Web Locks, so stand one in: a queue keyed by name, plus stealing.
 *
 * Stealing is modelled the way the platform behaves — the holder's `request`
 * promise rejects while its callback goes on running — because that rejection is
 * the whole mechanism a sign-out in another tab relies on.
 */
function stubLocks(): void {
  const holders = new Map<string, { reject: (error: Error) => void }[]>();
  const queue = new Map<string, Promise<unknown>>();

  const request = async (
    name: string,
    optionsOrRun: { steal?: boolean } | (() => unknown),
    maybeRun?: () => unknown,
  ): Promise<unknown> => {
    const options = typeof optionsOrRun === 'function' ? {} : optionsOrRun;
    const run = (typeof optionsOrRun === 'function' ? optionsOrRun : maybeRun) as () => unknown;

    if (options.steal === true) {
      for (const holder of holders.get(name) ?? []) {
        holder.reject(new DOMException('lock stolen', 'AbortError'));
      }
      holders.set(name, []);
      queue.delete(name);
      // A steal becomes the holder in its turn, so a later steal has something
      // to take — which is how the platform behaves, and what a lock held across
      // a span rather than a call depends on.
      return new Promise((resolve, reject) => {
        const entry = { reject };
        holders.set(name, [entry]);
        void Promise.resolve()
          .then(run)
          .then(resolve, reject)
          .finally(() => {
            holders.set(
              name,
              (holders.get(name) ?? []).filter((held) => held !== entry),
            );
          });
      });
    }

    const previous = queue.get(name) ?? Promise.resolve();
    const mine = previous.then(
      () =>
        new Promise((resolve, reject) => {
          const entry = { reject };
          holders.set(name, [...(holders.get(name) ?? []), entry]);
          void Promise.resolve()
            .then(run)
            .then(resolve, reject)
            .finally(() => {
              holders.set(
                name,
                (holders.get(name) ?? []).filter((held) => held !== entry),
              );
            });
        }),
    );
    queue.set(
      name,
      mine.catch(() => undefined),
    );
    return mine;
  };

  vi.stubGlobal('navigator', { locks: { request } });
}

afterEach(() => vi.unstubAllGlobals());

describe('withMintLock', () => {
  it('runs the work and returns its result', async () => {
    stubLocks();
    await expect(withMintLock('mint', async () => 'done')).resolves.toBe('done');
  });

  it('runs the work where the environment has no lock', async () => {
    vi.stubGlobal('navigator', {});
    const run = vi.fn(async () => 'done');

    await expect(withMintLock('mint', run)).resolves.toBe('done');
    expect(run).toHaveBeenCalledTimes(1);
  });

  it('runs the work unserialised where no other tab could read the store', async () => {
    stubLocks();
    const order: string[] = [];

    // A null name is what a store reporting `shared: false` produces: there is
    // nothing another tab could adopt, so serialising would spread the mints
    // without preventing any of them.
    const first = withMintLock(null, async () => {
      order.push('first in');
      await new Promise((resolve) => setTimeout(resolve, 10));
      order.push('first out');
    });
    const second = withMintLock(null, async () => {
      order.push('second in');
    });
    await Promise.all([first, second]);

    expect(order).toEqual(['first in', 'second in', 'first out']);
  });

  it('holds the lock for the work, so a second caller waits', async () => {
    stubLocks();
    const order: string[] = [];

    const first = withMintLock('mint', async () => {
      order.push('first in');
      await new Promise((resolve) => setTimeout(resolve, 10));
      order.push('first out');
    });
    const second = withMintLock('mint', async () => {
      order.push('second in');
    });
    await Promise.all([first, second]);

    expect(order).toEqual(['first in', 'first out', 'second in']);
  });

  it('lets a failure through and still frees the lock', async () => {
    stubLocks();

    // A mint that throws must not leave the name held: the next tab to want a
    // delegation would wait for a holder that is never coming back.
    await expect(
      withMintLock('mint', async () => {
        throw new Error('mint failed');
      }),
    ).rejects.toThrow('mint failed');
    await expect(withMintLock('mint', async () => 'after')).resolves.toBe('after');
  });

  it('hands the work a signal that does not fire while the lock is held', async () => {
    stubLocks();
    let seen: boolean | undefined;

    await withMintLock('mint', async (stolen) => {
      seen = stolen.aborted;
    });

    expect(seen).toBe(false);
  });

  it('fires the signal when the lock is taken away', async () => {
    stubLocks();
    let release!: () => void;
    let abortedAtWrite: boolean | undefined;

    // A mint in flight: it has made its calls and has not written yet.
    const mint = withMintLock('mint', async (signal) => {
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      // Read where the real mint reads it — after the calls return, before
      // anything is written. Asserting on the signal from outside would be
      // asking whether a microtask had run yet, which is not the contract.
      abortedAtWrite = signal.aborted;
      if (signal.aborted) throw new Error('stolen');
      return 'written';
    }).catch((error: Error) => error.message);

    await Promise.resolve();
    await stealMintLock('mint');

    release();
    // Two separate facts. The caller learns of the steal at once, from the
    // platform, and does not wait for the mint. The mint learns of it where it
    // matters — after its calls return, before it writes — and throws its result
    // away rather than storing it. The work could not be recalled; the signal is
    // what stops it landing.
    await expect(mint).resolves.toBe('lock stolen');
    expect(abortedAtWrite).toBe(true);
  });

  it('does not wait for the holder it steals from', async () => {
    stubLocks();
    let release!: () => void;
    const order: string[] = [];

    const mint = withMintLock('mint', async () => {
      order.push('mint in');
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      order.push('mint out');
    }).catch(() => undefined);

    await Promise.resolve();
    await stealMintLock('mint');
    // A sign-out the user asked for must not queue behind a canister call in
    // another tab.
    order.push('stolen');

    release();
    await mint;
    expect(order).toEqual(['mint in', 'stolen', 'mint out']);
  });

  it('steals nothing where there is no lock to steal', async () => {
    vi.stubGlobal('navigator', {});
    await expect(stealMintLock('mint')).resolves.toBeUndefined();
    await expect(stealMintLock(null)).resolves.toBeUndefined();
  });
});

describe('stealLock', () => {
  it('holds the lock until released, and says nothing happened', async () => {
    stubLocks();
    const held = stealLock('ceremony');

    await Promise.resolve();
    expect(held.stolen.aborted).toBe(false);

    held.release();
    await Promise.resolve();
    expect(held.stolen.aborted).toBe(false);
  });

  it('tells the incumbent it lost the lock', async () => {
    stubLocks();
    const first = stealLock('ceremony');
    await Promise.resolve();

    const second = stealLock('ceremony');
    // The steal is what the incumbent learns from; nothing waits for it.
    await Promise.resolve();
    await Promise.resolve();

    expect(first.stolen.aborted).toBe(true);
    expect(second.stolen.aborted).toBe(false);
    second.release();
  });

  it('leaves a different lock alone', async () => {
    stubLocks();
    const channel = stealLock('channel');
    await Promise.resolve();

    stealLock('sign-in');
    await Promise.resolve();
    await Promise.resolve();

    expect(channel.stolen.aborted).toBe(false);
  });

  it('releasing twice, or after a steal, does nothing', async () => {
    stubLocks();
    const held = stealLock('ceremony');
    await Promise.resolve();
    stealLock('ceremony');
    await Promise.resolve();

    expect(() => {
      held.release();
      held.release();
    }).not.toThrow();
  });

  // Coordination may only ever suppress work, never be required for it.
  it('runs without a lock where the platform has none', async () => {
    vi.stubGlobal('navigator', {});
    const held = stealLock('ceremony');

    await Promise.resolve();
    expect(held.stolen.aborted).toBe(false);
    expect(() => held.release()).not.toThrow();
  });
});
