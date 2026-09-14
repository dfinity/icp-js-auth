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

// `pointerdown` covers a mouse, a finger and a pen in one, which is the only
// press event a phone reliably produces.
const events = ['pointerdown', 'mousedown', 'mousemove', 'keydown', 'touchstart', 'wheel'];

/**
 * Where the tabs of an origin record that somebody is here.
 *
 * One fixed name, and deliberately not per client: being at the keyboard is a
 * fact about the person at this origin, so two managers on a page sharing it is
 * the right answer rather than a collision.
 */
const ACTIVITY_KEY = 'ic-last-active';

/**
 * How coarse the shared activity stamp is.
 *
 * Two consequences, both of them the point: a tab writes at most once every five
 * seconds however hard the user is working, and an idle deadline can therefore
 * fire up to five seconds early. Both are the right size for a timeout measured
 * in minutes.
 */
const ACTIVITY_RESOLUTION_MS = 5_000;

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
  #onForeground: () => void;
  #stampedAt = 0;

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

    // Coming back to the app is activity, and on a phone it is often the only
    // signal there is: switching apps or locking the screen produces no press
    // events, and a page that is frozen produces nothing at all.
    this.#onForeground = () => {
      if (document.visibilityState !== 'hidden') this.#resetTimer();
    };

    window.addEventListener('load', this.#resetTimer, true);
    window.addEventListener('focus', this.#onForeground, true);
    document.addEventListener('visibilitychange', this.#onForeground, true);

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
    window.removeEventListener('focus', this.#onForeground, true);
    document.removeEventListener('visibilitychange', this.#onForeground, true);

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
    this.#stamp();
    window.clearTimeout(this.#timeoutID);
    this.#timeoutID = window.setTimeout(() => this.#check(), this.#idleTimeout);
  }

  /** Tells the other tabs of this origin that somebody is here. */
  #stamp(): void {
    const now = Date.now();
    if (now - this.#stampedAt < ACTIVITY_RESOLUTION_MS) return;
    this.#stampedAt = now;
    try {
      window.localStorage.setItem(ACTIVITY_KEY, String(now));
    } catch {
      // No store to share through, so this tab is on its own — which costs the
      // cross-tab part and nothing else. Idle detection is a convenience.
    }
  }

  /**
   * Decides whether the window has really passed, and re-arms where it has not.
   *
   * The timer firing is not evidence of anything: it saw only this document's
   * events, and a browser throttles a background timer to a minute or more and
   * runs none at all while a tab is frozen — so a suspended tab's timeout can
   * fire the moment it resumes, or an hour late. Elapsed time is read from the
   * clock instead, and from a stamp every tab of the origin writes, so working in
   * one tab postpones the deadline in all of them.
   */
  #check(): void {
    const quiet = Date.now() - this.#lastActive();
    if (quiet < this.#idleTimeout) {
      // The remainder rather than a fixed interval, so this converges on the real
      // deadline instead of polling until it arrives.
      this.#timeoutID = window.setTimeout(() => this.#check(), this.#idleTimeout - quiet);
      return;
    }
    this.exit();
  }

  #lastActive(): number {
    try {
      const raw = window.localStorage.getItem(ACTIVITY_KEY);
      // A missing or unreadable stamp reads as "nobody, ever", which is what this
      // tab's own timer already believed.
      return raw === null ? 0 : Number(raw) || 0;
    } catch {
      return 0;
    }
  }
}
