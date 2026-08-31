import { afterEach, describe, expect, it, vi } from 'vitest';
import { withMintLock } from '../../src/client/app-lock.ts';

/**
 * jsdom has no Web Locks, so stand one in: a queue keyed by name, which is the
 * one property the mechanism depends on.
 */
function stubLocks(): void {
  const held = new Map<string, Promise<unknown>>();
  vi.stubGlobal('navigator', {
    locks: {
      request: async (name: string, run: () => Promise<unknown>) => {
        const previous = held.get(name) ?? Promise.resolve();
        const mine = previous.then(run);
        held.set(
          name,
          mine.catch(() => undefined),
        );
        return mine;
      },
    },
  });
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
});
