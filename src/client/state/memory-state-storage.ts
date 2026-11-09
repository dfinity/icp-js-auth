import type { SessionState, StateStorage } from './state-storage.js';

/**
 * State held for the lifetime of the instance and shared with nothing.
 *
 * For tests, and for a client that should share its sign-in with nothing: a
 * reload starts from nothing.
 * @see implements {@link StateStorage}
 */
export class MemoryStateStorage implements StateStorage {
  #state = new Map<string, Omit<SessionState, 'held'>>();
  #subscribers = new Map<string, Set<() => void>>();

  public get(key: string): SessionState | null {
    // Nothing reaches past this instance, so a record here is always one it holds.
    const state = this.#state.get(key);
    return state === undefined ? null : { ...state, held: true };
  }

  public set(key: string, state: Omit<SessionState, 'held'>): void {
    this.#state.set(key, state);
    this.#fire(key);
  }

  public remove(key: string): void {
    this.#state.delete(key);
    this.#fire(key);
  }

  /** The same as {@link remove}: this store publishes nothing at all. */
  public discard(key: string): void {
    this.remove(key);
  }

  /**
   * Fires when the state changes, which here means when something writes to
   * this instance.
   *
   * Nothing outside the process can reach a `Map`, so a medium is not what makes
   * this worth having: two clients can be handed the same instance, and this is
   * how the one that did not write finds out. Each listener is told only when the
   * record actually changed since it was last told, so a client's own writes do
   * not come back to it as news.
   */
  public subscribe(key: string, listener: () => void): () => void {
    let last = this.#raw(key);
    const check = (): void => {
      const now = this.#raw(key);
      if (now !== last) {
        last = now;
        listener();
      }
    };
    const listeners = this.#subscribers.get(key) ?? new Set();
    listeners.add(check);
    this.#subscribers.set(key, listeners);

    return () => {
      listeners.delete(check);
    };
  }

  #fire(key: string): void {
    for (const check of [...(this.#subscribers.get(key) ?? [])]) check();
  }

  // The same shape `LocalStateStorage` keeps, so "changed" means the same thing
  // in both: a record is one string, and comparing strings needs no field walk.
  #raw(key: string): string | null {
    const state = this.#state.get(key);
    return state === undefined
      ? null
      : `${state.principal.toText()}|${state.expiration.toString()}`;
  }
}
