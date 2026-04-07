import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
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

afterEach(() => {
  // Tear down the singleton so each test starts fresh.
  IdleManager.create().exit();
});

describe('IdleManager', () => {
  it('should call its callback after time spent inactive', () => {
    const cb = vi.fn();
    IdleManager.create({ onIdle: cb, captureScroll: true });
    expect(cb).not.toHaveBeenCalled();
    // simulate user being inactive for 10 minutes
    vi.advanceTimersByTime(10 * MILLISECONDS_PER_MINUTE);
    expect(cb).toHaveBeenCalled();
  });

  it('should return the same instance on subsequent create calls', () => {
    const a = IdleManager.create();
    const b = IdleManager.create();
    expect(a).toBe(b);
  });

  it('should register additional callbacks from subsequent create calls', () => {
    const cb1 = vi.fn();
    const cb2 = vi.fn();
    IdleManager.create({ onIdle: cb1 });
    IdleManager.create({ onIdle: cb2 });

    vi.advanceTimersByTime(10 * MILLISECONDS_PER_MINUTE);
    expect(cb1).toHaveBeenCalled();
    expect(cb2).toHaveBeenCalled();
  });

  it('should allow a fresh instance after exit', () => {
    const a = IdleManager.create();
    a.exit();
    const b = IdleManager.create();
    expect(a).not.toBe(b);
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

  it('should allow configuration of the timeout', () => {
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
});
