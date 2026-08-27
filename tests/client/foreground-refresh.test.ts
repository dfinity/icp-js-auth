import { afterEach, describe, expect, it, vi } from 'vitest';

import { watchForeground } from '../../src/client/foreground-refresh.ts';

afterEach(() => {
  vi.unstubAllGlobals();
  // Spies are not undone by unstubAllGlobals, and the visibilityState getter is
  // spied on below. Left in place it reads 'hidden' for every test after it, in
  // a file whose remaining tests are about firing when the page is visible.
  vi.restoreAllMocks();
});

describe('watchForeground', () => {
  it('fires when the page becomes visible', () => {
    const onForeground = vi.fn();
    const unwatch = watchForeground(onForeground);

    document.dispatchEvent(new Event('visibilitychange'));

    expect(onForeground).toHaveBeenCalledTimes(1);
    unwatch?.();
  });

  it('ignores a visibility change that hid the page', () => {
    const onForeground = vi.fn();
    const unwatch = watchForeground(onForeground);
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');

    document.dispatchEvent(new Event('visibilitychange'));

    expect(onForeground).not.toHaveBeenCalled();
    unwatch?.();
  });

  it('fires on focus, which a second visible window does not change visibility for', () => {
    const onForeground = vi.fn();
    const unwatch = watchForeground(onForeground);

    globalThis.dispatchEvent(new Event('focus'));

    expect(onForeground).toHaveBeenCalledTimes(1);
    unwatch?.();
  });

  it('fires on pageshow, for a page restored with timers that never ran', () => {
    const onForeground = vi.fn();
    const unwatch = watchForeground(onForeground);

    globalThis.dispatchEvent(new Event('pageshow'));

    expect(onForeground).toHaveBeenCalledTimes(1);
    unwatch?.();
  });

  it('stops firing once unhooked', () => {
    const onForeground = vi.fn();
    watchForeground(onForeground)?.();

    document.dispatchEvent(new Event('visibilitychange'));
    globalThis.dispatchEvent(new Event('focus'));
    globalThis.dispatchEvent(new Event('pageshow'));

    expect(onForeground).not.toHaveBeenCalled();
  });

  it('hooks nothing where there is no DOM', () => {
    vi.stubGlobal('document', undefined);

    expect(watchForeground(vi.fn())).toBeUndefined();
  });
});
