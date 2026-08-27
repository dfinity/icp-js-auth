import type { SignIdentity } from '@icp-sdk/core/agent';
import { Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import type { IdentityStorage } from './identity-storage.js';

// Storage slot suffix the key lives under, combined with the instance prefix.
// Owned by this implementation.
//
// Distinct from the slot the pre-session client used ('identity'), because what
// is stored is no longer the same thing: that slot held the key an application's
// own delegations were issued to, and this one holds the key that mints them.
// Reading the old value here would put a key to work in a role it was never
// issued for.
const STORAGE_KEY = 'session-identity';

/**
 * Legacy identity storage: an Ed25519 key pair in `localStorage`, for
 * environments where IndexedDB or non-extractable `CryptoKey` is unavailable.
 *
 * Unlike {@link IdbIdentityStorage}, the private key is extractable and stored
 * in plaintext (Ed25519 has no non-extractable form), so it is readable by any
 * script on the origin. Prefer {@link IdbIdentityStorage} unless it cannot run.
 * @see implements {@link IdentityStorage}
 */
export class LocalIdentityStorage implements IdentityStorage {
  constructor(
    public readonly prefix = 'ic-',
    private readonly _localStorage?: Storage,
  ) {}

  // These are `async` so a synchronous failure in `#ls()` (no localStorage)
  // surfaces as a promise rejection, matching the async IdentityStorage
  // contract, rather than throwing out of the call before a Promise exists.
  public async create(): Promise<SignIdentity> {
    // Mint only — persisted by set() once a delegation is obtained.
    return Ed25519KeyIdentity.generate();
  }

  public async set(identity: SignIdentity): Promise<void> {
    if (!(identity instanceof Ed25519KeyIdentity)) {
      throw new Error('LocalIdentityStorage can only persist an identity from its own create()');
    }
    this.#ls().setItem(this.prefix + STORAGE_KEY, JSON.stringify(identity.toJSON()));
  }

  public async get(): Promise<SignIdentity | null> {
    const raw = this.#ls().getItem(this.prefix + STORAGE_KEY);
    if (raw === null) return null;
    try {
      return Ed25519KeyIdentity.fromJSON(raw);
    } catch {
      return null;
    }
  }

  public async remove(): Promise<void> {
    this.#ls().removeItem(this.prefix + STORAGE_KEY);
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
