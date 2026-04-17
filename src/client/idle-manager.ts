type IdleCB = () => unknown;

export type IdleManagerOptions = {
  /**
   * Callback after the user has gone idle
   */
  onIdle?: IdleCB;
  /**
   * timeout in ms
   * @default 30 minutes [600_000]
   */
  idleTimeout?: number;
  /**
   * capture scroll events
   * @default false
   */
  captureScroll?: boolean;
  /**
   * scroll debounce time in ms
   * @default 100
   */
  scrollDebounce?: number;
};

const events = ['mousedown', 'mousemove', 'keydown', 'touchstart', 'wheel'];

/**
 * Detects if the user has been idle for a duration of `idleTimeout` ms, and calls `onIdle` and registered callbacks.
 * By default, the IdleManager will log a user out after 10 minutes of inactivity.
 * To override these defaults, you can pass an `onIdle` callback, or configure a custom `idleTimeout` in milliseconds.
 *
 * IdleManager is a singleton: multiple calls to `create()` return the same instance,
 * registering any new `onIdle` callback. Call `exit()` to tear down the singleton.
 */
export class IdleManager {
  static #instance: IdleManager | undefined;

  #callbacks: IdleCB[] = [];
  #idleTimeout: number;
  #timeoutID?: number = undefined;
  #resetTimer: () => void;

  /**
   * Creates or returns the singleton {@link IdleManager}.
   * If the instance already exists, any provided `onIdle` callback is registered
   * on the existing instance.
   * @param {IdleManagerOptions} options Optional configuration
   * @see {@link IdleManagerOptions}
   * @param options.onIdle Callback once user has been idle. Use to prompt for fresh sign-in, and use `Actor.agentOf(your_actor).invalidateIdentity()` to protect the user
   * @param options.idleTimeout timeout in ms
   * @param options.captureScroll capture scroll events
   * @param options.scrollDebounce scroll debounce time in ms
   */
  public static create(
    options: {
      /**
       * Callback after the user has gone idle
       * @see {@link IdleCB}
       */
      onIdle?: () => unknown;
      /**
       * timeout in ms
       * @default 10 minutes [600_000]
       */
      idleTimeout?: number;
      /**
       * capture scroll events
       * @default false
       */
      captureScroll?: boolean;
      /**
       * scroll debounce time in ms
       * @default 100
       */
      scrollDebounce?: number;
    } = {},
  ): IdleManager {
    if (IdleManager.#instance) {
      if (options.onIdle) {
        IdleManager.#instance.registerCallback(options.onIdle);
      }
      return IdleManager.#instance;
    }
    const instance = new IdleManager(options);
    IdleManager.#instance = instance;
    return instance;
  }

  /**
   * @param options {@link IdleManagerOptions}
   */
  private constructor(options: IdleManagerOptions = {}) {
    const { onIdle, idleTimeout = 10 * 60 * 1000 } = options || {};

    this.#callbacks = onIdle ? [onIdle] : [];
    this.#idleTimeout = idleTimeout;

    // Store the bound function once so the same reference is used
    // for both addEventListener and removeEventListener.
    this.#resetTimer = this._resetTimer.bind(this);

    window.addEventListener('load', this.#resetTimer, true);

    events.forEach((name) => {
      document.addEventListener(name, this.#resetTimer, true);
    });

    const debounce = (func: (...args: unknown[]) => void, wait: number) => {
      let timeout: number | undefined;
      return (...args: unknown[]) => {
        const context = this;
        const later = () => {
          timeout = undefined;
          func.apply(context, args);
        };
        clearTimeout(timeout);
        timeout = window.setTimeout(later, wait);
      };
    };

    if (options?.captureScroll) {
      // debounce scroll events
      const scroll = debounce(this.#resetTimer, options?.scrollDebounce ?? 100);
      window.addEventListener('scroll', scroll, true);
    }

    this.#resetTimer();
  }

  /**
   * @param {IdleCB} callback function to be called when user goes idle
   */
  public registerCallback(callback: IdleCB): void {
    this.#callbacks.push(callback);
  }

  /**
   * Tears down listeners, fires all callbacks, and clears the singleton.
   */
  public exit(): void {
    clearTimeout(this.#timeoutID);
    window.removeEventListener('load', this.#resetTimer, true);

    events.forEach((name) => {
      document.removeEventListener(name, this.#resetTimer, true);
    });
    this.#callbacks.forEach((cb) => {
      cb();
    });

    IdleManager.#instance = undefined;
  }

  /**
   * Resets the timeouts during cleanup
   */
  private _resetTimer(): void {
    const exit = this.exit.bind(this);
    window.clearTimeout(this.#timeoutID);
    this.#timeoutID = window.setTimeout(exit, this.#idleTimeout);
  }
}
