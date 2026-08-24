import type { DerEncodedPublicKey } from '@icp-sdk/core/agent';
import { DelegationChain } from '@icp-sdk/core/identity';
import { fromBase64, toBase64 } from './base64.js';
import type { Session, SessionStorage } from './session-storage.js';

// Default storage slot the serialized session lives under. Owned by
// this implementation; override per instance via the constructor.
const DEFAULT_KEY = 'ic-delegation';

/**
 * Default session storage: the session in `localStorage`, with
 * change notifications on both same-tab writes and cross-tab `storage` events.
 *
 * A `set` or `remove` on this tab notifies this tab's subscribers directly; a
 * write in another tab arrives as a `storage` event. Either way each subscriber
 * fires only when the stored value actually changed, so a write and a
 * coincidental event don't notify twice. The session is stored per origin, so
 * nothing outside this origin can read it.
 * @see implements {@link SessionStorage}
 */
export class LocalSessionStorage implements SessionStorage {
  // Per-subscriber checks, invoked on a same-tab write or a `storage` event.
  #subscribers = new Set<() => void>();

  constructor(
    public readonly key = DEFAULT_KEY,
    private readonly _localStorage?: Storage,
  ) {}

  public get(): Session | null {
    const raw = this.#ls().getItem(this.key);
    if (raw === null) return null;
    try {
      const { chain, accountKey } = JSON.parse(raw) as { chain: string; accountKey: string };
      return {
        chain: DelegationChain.fromJSON(chain),
        accountKey: fromBase64(accountKey) as DerEncodedPublicKey,
      };
    } catch {
      return null;
    }
  }

  public set(session: Session): void {
    this.#ls().setItem(
      this.key,
      JSON.stringify({
        chain: JSON.stringify(session.chain.toJSON()),
        accountKey: toBase64(session.accountKey),
      }),
    );
    this.#fire();
  }

  public remove(): void {
    this.#ls().removeItem(this.key);
    this.#fire();
  }

  // Nothing here reaches past this origin, so there is nothing to leave alone.
  public discard(): void {
    this.remove();
  }

  public subscribe(listener: () => void): () => void {
    // Fire only when the stored value actually changed, so a same-tab write and
    // a coincidental `storage` event don't notify twice.
    let last = this.#snapshot();
    const check = () => {
      const snapshot = this.#snapshot();
      if (snapshot !== last) {
        last = snapshot;
        listener();
      }
    };
    this.#subscribers.add(check);

    const store = this.#ls();
    const onStorage = (event: StorageEvent) => {
      // Ignore events from a different Storage area (e.g. sessionStorage) that
      // happen to use the same key. `event.key` is null when the whole store is
      // cleared; treat that as a change to our key too.
      if (event.storageArea !== store) return;
      if (event.key === this.key || event.key === null) check();
    };
    globalThis.addEventListener('storage', onStorage);

    return () => {
      this.#subscribers.delete(check);
      globalThis.removeEventListener('storage', onStorage);
    };
  }

  #fire(): void {
    for (const check of this.#subscribers) check();
  }

  #snapshot(): string {
    return this.#ls().getItem(this.key) ?? '';
  }

  #ls(): Storage {
    if (this._localStorage) {
      return this._localStorage;
    }
    const ls = globalThis.localStorage;
    if (!ls) {
      throw new Error('Could not find local storage.');
    }
    return ls;
  }
}
