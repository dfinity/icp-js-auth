type IdleCB = () => unknown;

export type IdleManagerOptions = {
  /**
   * Callback after the user has gone idle.
   */
  onIdle?: IdleCB;
  /**
   * Timeout in ms before the user is considered idle.
   * @default 600_000 (10 minutes)
   */
  idleTimeout?: number;
  /**
   * Capture scroll events as user activity.
   * @default false
   */
  captureScroll?: boolean;
  /**
   * Scroll debounce time in ms.
   * @default 100
   */
  scrollDebounce?: number;
};

const ACTIVITY_EVENTS = ['mousedown', 'mousemove', 'keydown', 'touchstart', 'wheel'];
const DEFAULT_IDLE_TIMEOUT = 10 * 60 * 1000;

/**
 * Detects user inactivity and fires registered callbacks after a configurable
 * timeout. A single shared instance is used across all consumers — calling
 * {@link IdleManager.create} multiple times returns the same manager so that
 * only one set of DOM event listeners and one timer exists at any time.
 */
export class IdleManager {
  static #instance: IdleManager | undefined;

  #callbacks: IdleCB[] = [];
  #idleTimeout: number;
  #timeoutID: number | undefined;
  #resetTimer: () => void;

  /**
   * Returns the shared IdleManager, creating it on first call.
   * Subsequent calls register additional `onIdle` callbacks but
   * do not create new listeners or timers.
   *
   * @param options - Configuration for the idle manager.
   * @param options.onIdle - Callback when user goes idle.
   * @param options.idleTimeout - Timeout in ms.
   * @param options.captureScroll - Capture scroll events as activity.
   * @param options.scrollDebounce - Scroll debounce time in ms.
   */
  static create(options: IdleManagerOptions = {}): IdleManager {
    if (!IdleManager.#instance) {
      IdleManager.#instance = new IdleManager(options);
    } else if (options.onIdle) {
      // Additional consumers register their callback on the shared instance.
      IdleManager.#instance.registerCallback(options.onIdle);
    }
    return IdleManager.#instance;
  }

  private constructor(options: IdleManagerOptions = {}) {
    const { onIdle, idleTimeout = DEFAULT_IDLE_TIMEOUT } = options;

    this.#callbacks = onIdle ? [onIdle] : [];
    this.#idleTimeout = idleTimeout;
    this.#resetTimer = this.#reset.bind(this);

    window.addEventListener('load', this.#resetTimer, true);
    for (const name of ACTIVITY_EVENTS) {
      document.addEventListener(name, this.#resetTimer, true);
    }

    if (options.captureScroll) {
      const scrollDebounce = options.scrollDebounce ?? 100;
      let timeout: number | undefined;
      const debouncedReset = () => {
        clearTimeout(timeout);
        timeout = window.setTimeout(this.#resetTimer, scrollDebounce);
      };
      window.addEventListener('scroll', debouncedReset, true);
    }

    this.#reset();
  }

  /**
   * Registers a callback to fire when the user goes idle.
   * @param callback - Function to call on idle.
   */
  registerCallback(callback: IdleCB): void {
    this.#callbacks.push(callback);
  }

  /**
   * Tears down the idle manager: clears the timer, removes all listeners,
   * fires all callbacks, and releases the singleton so the next
   * {@link IdleManager.create} call starts fresh.
   */
  exit(): void {
    clearTimeout(this.#timeoutID);
    window.removeEventListener('load', this.#resetTimer, true);
    for (const name of ACTIVITY_EVENTS) {
      document.removeEventListener(name, this.#resetTimer, true);
    }
    for (const cb of this.#callbacks) {
      cb();
    }
    this.#callbacks = [];
    IdleManager.#instance = undefined;
  }

  #reset(): void {
    window.clearTimeout(this.#timeoutID);
    this.#timeoutID = window.setTimeout(() => this.exit(), this.#idleTimeout);
  }
}
