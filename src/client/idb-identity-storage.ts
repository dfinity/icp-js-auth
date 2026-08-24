import type { SignIdentity } from '@icp-sdk/core/agent';
import { ECDSAKeyIdentity } from '@icp-sdk/core/identity';
import { type DBCreateOptions, IdbKeyVal } from './db.js';
import type { IdentityStorage } from './identity-storage.js';

// Storage slot the key pair lives under. Owned by this implementation.
const STORAGE_KEY = 'identity';

/**
 * Default identity storage: a non-extractable ECDSA (P-256) key pair in
 * IndexedDB.
 *
 * Non-extractable means the private key never leaves the browser's key store —
 * it cannot be serialized to a string, which is why it lives in IndexedDB (via
 * structured clone of the `CryptoKeyPair`) rather than `localStorage`. Use
 * {@link LocalIdentityStorage} only where IndexedDB or `CryptoKey` is
 * unavailable.
 * @see implements {@link IdentityStorage}
 */
export class IdbIdentityStorage implements IdentityStorage {
  #options: DBCreateOptions;

  /**
   * @param options - DBCreateOptions
   * @param options.dbName - name for the indexeddb database
   * @param options.storeName - name for the indexeddb Data Store
   * @param options.version - version of the database. Increment to safely upgrade
   * @example
   * ```ts
   * const storage = new IdbIdentityStorage({ dbName: 'my-db', storeName: 'my-store', version: 2 });
   * ```
   */
  constructor(options?: DBCreateOptions) {
    this.#options = options ?? {};
  }

  // Initializes a KeyVal on first request.
  #dbPromise: Promise<IdbKeyVal> | null = null;
  get #db(): Promise<IdbKeyVal> {
    if (this.#dbPromise === null) {
      const promise = IdbKeyVal.create(this.#options).catch((error) => {
        if (this.#dbPromise === promise) {
          this.#dbPromise = null;
        }
        throw error;
      });
      this.#dbPromise = promise;
    }
    return this.#dbPromise;
  }

  public async create(): Promise<SignIdentity> {
    // Mint only — persisted by set() once a delegation is obtained.
    return ECDSAKeyIdentity.generate({ extractable: false });
  }

  public async set(identity: SignIdentity): Promise<void> {
    if (!(identity instanceof ECDSAKeyIdentity)) {
      throw new Error('IdbIdentityStorage can only persist an identity from its own create()');
    }
    const db = await this.#db;
    await db.set(STORAGE_KEY, identity.getKeyPair());
  }

  public async get(): Promise<SignIdentity | null> {
    const db = await this.#db;
    const keyPair = await db.get<CryptoKeyPair>(STORAGE_KEY);
    if (keyPair === null) return null;
    try {
      return await ECDSAKeyIdentity.fromKeyPair(keyPair);
    } catch {
      return null;
    }
  }

  public async remove(): Promise<void> {
    const db = await this.#db;
    await db.remove(STORAGE_KEY);
  }
}
