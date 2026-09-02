import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { IdleManager } from '../../src/client/idle-manager.ts';

const MILLISECONDS_PER_SECOND = 1000;
const MILLISECONDS_PER_MINUTE = MILLISECONDS_PER_SECOND * 60;

beforeAll(() => {
  vi.useFakeTimers();

  Object.defineProperty(window, 'location', {
    writable: true,
    value: { assign: vi.fn(), reload: vi.fn() },
  });
});

beforeEach(() => {
  // The activity stamp is shared by every tab of the origin, so it is also shared
  // by every test in this file.
  localStorage.clear();
});

afterEach(() => {
  // Tear down the singleton between tests so each test starts fresh.
  try {
    IdleManager.create().exit();
  } catch {
    // ignore if already torn down
  }
});

describe('IdleManager', () => {
  it('should call its callback after time spent inactive', () => {
    const cb = vi.fn();
    const manager = IdleManager.create({ onIdle: cb, captureScroll: true });
    expect(cb).not.toHaveBeenCalled();
    // simulate user being inactive for 10 minutes
    vi.advanceTimersByTime(10 * MILLISECONDS_PER_MINUTE);
    expect(cb).toHaveBeenCalled();
    manager.exit();
  });

  it('should replace the default callback if a callback is passed during creation', () => {
    const idleFn = vi.fn();
    IdleManager.create({ onIdle: idleFn });

    expect(window.location.reload).not.toHaveBeenCalled();
    // simulate user being inactive for 10 minutes
    vi.advanceTimersByTime(10 * MILLISECONDS_PER_MINUTE);
    expect(window.location.reload).not.toHaveBeenCalled();
    expect(idleFn).toBeCalled();
  });

  it('should replace the default callback if a callback is registered', () => {
    const manager = IdleManager.create();

    manager.registerCallback(vi.fn());

    expect(window.location.reload).not.toHaveBeenCalled();
    // simulate user being inactive for 10 minutes
    vi.advanceTimersByTime(10 * MILLISECONDS_PER_MINUTE);
    expect(window.location.reload).not.toHaveBeenCalled();
  });

  it('should delay allow configuration of the timeout', () => {
    const cb = vi.fn();
    const extraDelay = 100;
    IdleManager.create({ onIdle: cb, idleTimeout: 10 * MILLISECONDS_PER_MINUTE + extraDelay });
    expect(cb).not.toHaveBeenCalled();
    // simulate user being inactive for 10 minutes
    vi.advanceTimersByTime(10 * MILLISECONDS_PER_MINUTE);
    expect(cb).not.toHaveBeenCalled();
    vi.advanceTimersByTime(extraDelay);
    expect(cb).toHaveBeenCalled();
  });

  it('should delay its callback on keyboard events', () => {
    const cb = vi.fn();
    IdleManager.create({ onIdle: cb });
    expect(cb).not.toHaveBeenCalled();
    // simulate user being inactive for 9 minutes
    vi.advanceTimersByTime(9 * MILLISECONDS_PER_MINUTE);
    expect(cb).not.toHaveBeenCalled();
    document.dispatchEvent(new KeyboardEvent('keydown'));

    // wait 5 minutes
    vi.advanceTimersByTime(5 * MILLISECONDS_PER_MINUTE);
    expect(cb).not.toHaveBeenCalled();
    // simulate user being inactive for 9 minutes
    vi.advanceTimersByTime(9 * MILLISECONDS_PER_MINUTE);
    expect(cb).toHaveBeenCalled();
  });

  it('should delay its callback on mouse events', () => {
    const cb = vi.fn();
    IdleManager.create({ onIdle: cb });
    expect(cb).not.toHaveBeenCalled();
    // simulate user being inactive for 9 minutes
    vi.advanceTimersByTime(9 * MILLISECONDS_PER_MINUTE);
    expect(cb).not.toHaveBeenCalled();
    // simulate user moving the mouse
    document.dispatchEvent(new MouseEvent('mousemove'));

    // wait 5 minutes
    vi.advanceTimersByTime(5 * MILLISECONDS_PER_MINUTE);
    expect(cb).not.toHaveBeenCalled();
    // simulate user being inactive for 9 minutes
    vi.advanceTimersByTime(9 * MILLISECONDS_PER_MINUTE);
    expect(cb).toHaveBeenCalled();
  });

  it('should delay its callback on touch events', () => {
    const cb = vi.fn();
    IdleManager.create({ onIdle: cb });
    expect(cb).not.toHaveBeenCalled();
    // simulate user being inactive for 9 minutes
    vi.advanceTimersByTime(9 * MILLISECONDS_PER_MINUTE);
    expect(cb).not.toHaveBeenCalled();
    // simulate user touching the screen
    document.dispatchEvent(new TouchEvent('touchstart'));

    // wait 5 minutes
    vi.advanceTimersByTime(5 * MILLISECONDS_PER_MINUTE);
    expect(cb).not.toHaveBeenCalled();
    // simulate user being inactive for 9 minutes
    vi.advanceTimersByTime(9 * MILLISECONDS_PER_MINUTE);
    expect(cb).toHaveBeenCalled();
  });

  it('should delay its callback on scroll events', () => {
    const cb = vi.fn();

    const scrollDebounce = 100;

    IdleManager.create({ onIdle: cb, captureScroll: true, scrollDebounce });
    expect(cb).not.toHaveBeenCalled();
    // simulate user being inactive for 9 minutes
    vi.advanceTimersByTime(9 * MILLISECONDS_PER_MINUTE);
    expect(cb).not.toHaveBeenCalled();
    // simulate user scrolling
    document.dispatchEvent(new WheelEvent('scroll'));

    // wait 5 minutes
    vi.advanceTimersByTime(5 * MILLISECONDS_PER_MINUTE);
    expect(cb).not.toHaveBeenCalled();
    // simulate user being inactive for 9 minutes, plus the debounce
    vi.advanceTimersByTime(9 * MILLISECONDS_PER_MINUTE + scrollDebounce);
    expect(cb).toHaveBeenCalled();
  });

  it('should return the same instance on multiple create() calls', () => {
    const instance1 = IdleManager.create();
    const instance2 = IdleManager.create();
    expect(instance1).toBe(instance2);
  });

  it('should return a fresh instance after exit()', () => {
    const instance1 = IdleManager.create();
    instance1.exit();
    const instance2 = IdleManager.create();
    expect(instance1).not.toBe(instance2);
  });

  it('should fire callbacks from multiple create() calls when idle', () => {
    const cb1 = vi.fn();
    const cb2 = vi.fn();
    IdleManager.create({ onIdle: cb1 });
    IdleManager.create({ onIdle: cb2 });

    // simulate user being inactive for 10 minutes
    vi.advanceTimersByTime(10 * MILLISECONDS_PER_MINUTE);
    expect(cb1).toHaveBeenCalled();
    expect(cb2).toHaveBeenCalled();
  });

  it('does not sign out while another tab of the origin is being used', () => {
    const onIdle = vi.fn();
    const manager = IdleManager.create({ onIdle });

    // What a backgrounded tab looks like: no events reach it, so its own timer
    // says idle — while a sibling tab keeps stamping because the user is there.
    for (let minute = 0; minute < 20; minute++) {
      localStorage.setItem('ic-last-active', String(Date.now()));
      vi.advanceTimersByTime(MILLISECONDS_PER_MINUTE);
    }

    // Signing out here would end the session at the canister and take the tab the
    // user is actually working in down with it.
    expect(onIdle).not.toHaveBeenCalled();
    manager.exit();
  });

  it('signs out once no tab of the origin has been used for the window', () => {
    const onIdle = vi.fn();
    IdleManager.create({ onIdle });

    localStorage.setItem('ic-last-active', String(Date.now()));
    vi.advanceTimersByTime(5 * MILLISECONDS_PER_MINUTE);
    expect(onIdle).not.toHaveBeenCalled();

    // Nothing stamps from here on, so the window really does pass.
    vi.advanceTimersByTime(10 * MILLISECONDS_PER_MINUTE);
    expect(onIdle).toHaveBeenCalledTimes(1);
  });

  it('measures the window from the clock, not from when the timer happened to fire', () => {
    const onIdle = vi.fn();
    IdleManager.create({ onIdle });

    // A frozen tab: the browser runs no timers, then fires one on resume. Here
    // the stamp is recent, so the fire is early however late it arrived.
    localStorage.setItem('ic-last-active', String(Date.now() + 9 * MILLISECONDS_PER_MINUTE));
    vi.advanceTimersByTime(10 * MILLISECONDS_PER_MINUTE);

    expect(onIdle).not.toHaveBeenCalled();

    // And it re-arms for the remainder rather than polling: one more minute of
    // quiet is what is left of the window.
    vi.advanceTimersByTime(10 * MILLISECONDS_PER_MINUTE);
    expect(onIdle).toHaveBeenCalledTimes(1);
  });

  it('counts coming back to the app as activity', () => {
    const onIdle = vi.fn();
    const manager = IdleManager.create({ onIdle });

    vi.advanceTimersByTime(9 * MILLISECONDS_PER_MINUTE);
    // On a phone this is often the only signal there is: switching apps and
    // locking the screen produce no press events at all.
    document.dispatchEvent(new Event('visibilitychange'));
    vi.advanceTimersByTime(9 * MILLISECONDS_PER_MINUTE);

    expect(onIdle).not.toHaveBeenCalled();
    manager.exit();
  });

  it('delays its callback on a pointer press, which is what a phone sends', () => {
    const onIdle = vi.fn();
    const manager = IdleManager.create({ onIdle });

    vi.advanceTimersByTime(9 * MILLISECONDS_PER_MINUTE);
    document.dispatchEvent(new Event('pointerdown'));
    vi.advanceTimersByTime(9 * MILLISECONDS_PER_MINUTE);

    expect(onIdle).not.toHaveBeenCalled();
    manager.exit();
  });

  it('works alone where there is no store to share through', () => {
    const onIdle = vi.fn();
    const getItem = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('storage unavailable');
    });
    const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('storage unavailable');
    });

    IdleManager.create({ onIdle });
    vi.advanceTimersByTime(10 * MILLISECONDS_PER_MINUTE);

    // The cross-tab part is what is lost, not the watchdog: idle detection is a
    // convenience and never a security boundary.
    expect(onIdle).toHaveBeenCalledTimes(1);
    getItem.mockRestore();
    setItem.mockRestore();
  });

  it('announces its own activity, so the other tabs postpone their deadline', () => {
    const manager = IdleManager.create();
    const atStart = Number(localStorage.getItem('ic-last-active'));
    expect(atStart).toBeGreaterThan(0);

    vi.advanceTimersByTime(6 * MILLISECONDS_PER_SECOND);
    document.dispatchEvent(new Event('keydown'));

    // Without this write, a tab being used tells the others nothing and each one
    // still signs out on its own timer.
    expect(Number(localStorage.getItem('ic-last-active'))).toBeGreaterThan(atStart);
    manager.exit();
  });

  it('writes at most once per resolution however hard the user works', () => {
    const manager = IdleManager.create();
    const setItem = vi.spyOn(Storage.prototype, 'setItem');

    // A hundred events inside one resolution window: mousemove alone can produce
    // that in a second, and a write per event would be absurd.
    for (let i = 0; i < 100; i++) document.dispatchEvent(new Event('mousemove'));
    expect(setItem).not.toHaveBeenCalled();

    vi.advanceTimersByTime(6 * MILLISECONDS_PER_SECOND);
    document.dispatchEvent(new Event('mousemove'));
    expect(setItem).toHaveBeenCalledTimes(1);

    setItem.mockRestore();
    manager.exit();
  });
});
