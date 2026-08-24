import { afterEach, describe, expect, it, vi } from 'vitest';

import { withLock } from '../../src/client/app-lock.ts';

afterEach(() => vi.unstubAllGlobals());

describe('withLock', () => {
  it('runs the work and returns its result', async () => {
    await expect(withLock('mint', async () => 'done')).resolves.toBe('done');
  });

  it('runs the work where the environment has no lock', async () => {
    vi.stubGlobal('navigator', {});
    const run = vi.fn(async () => 'done');

    await expect(withLock('mint', run)).resolves.toBe('done');
    expect(run).toHaveBeenCalledTimes(1);
  });

  it('holds the lock for the work, so a second caller waits', async () => {
    // jsdom has no Web Locks, so stand one in: a queue keyed by name, which is
    // the property the mechanism depends on.
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

    const order: string[] = [];
    const first = withLock('mint', async () => {
      order.push('first in');
      await new Promise((resolve) => setTimeout(resolve, 10));
      order.push('first out');
    });
    const second = withLock('mint', async () => {
      order.push('second in');
    });
    await Promise.all([first, second]);

    expect(order).toEqual(['first in', 'first out', 'second in']);
  });

  it('lets a failure through and still frees the lock', async () => {
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

    await expect(
      withLock('mint', async () => {
        throw new Error('mint failed');
      }),
    ).rejects.toThrow('mint failed');
    await expect(withLock('mint', async () => 'after')).resolves.toBe('after');
  });
});
