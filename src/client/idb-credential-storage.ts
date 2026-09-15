import { DelegationChain, ECDSAKeyIdentity } from '@icp-sdk/core/identity';
import type { Credential, CredentialStorage } from './credential-storage.js';
import { type DBCreateOptions, IdbKeyVal } from './db.js';

/** What one slot holds in the database: a key handle, and the chain as JSON. */
interface StoredCredential {
  keyPair: CryptoKeyPair;
  chain?: string;
}

/**
 * Credentials in IndexedDB, which is what a browser offers that can hold a key
 * whose private half is unreadable.
 *
 * A non-extractable `CryptoKeyPair` survives a structured clone, so what another
 * tab reads is a handle that signs and cannot be exported — no key material is
 * written anywhere.
 * @see implements {@link CredentialStorage}
 */
export class IdbCredentialStorage implements CredentialStorage<ECDSAKeyIdentity> {
  public readonly shared = true;
  public readonly durable = true;

  #options: DBCreateOptions;

  /**
   * @param options - Database name, store name and version.
   */
  constructor(options?: DBCreateOptions) {
    this.#options = options ?? {};
  }

  // Opened on first use, and forgotten again if opening failed, so a later call
  // retries rather than reusing a rejected promise.
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

  public create(): Promise<ECDSAKeyIdentity> {
    return ECDSAKeyIdentity.generate({ extractable: false });
  }

  public async get(slot: string): Promise<Credential<ECDSAKeyIdentity> | null> {
    const db = await this.#db;
    const stored = await db.get<StoredCredential>(slot);
    if (!stored) return null;

    try {
      const identity = await ECDSAKeyIdentity.fromKeyPair(stored.keyPair);
      const chain = stored.chain === undefined ? undefined : DelegationChain.fromJSON(stored.chain);
      return { identity, chain };
    } catch {
      // A record written by an incompatible version, or one the browser has
      // truncated. Reporting nothing lets the caller acquire again, which is
      // safer than throwing on a page load.
      return null;
    }
  }

  public async set(slot: string, credential: Credential<ECDSAKeyIdentity>): Promise<void> {
    const db = await this.#db;
    await db.set<StoredCredential>(slot, {
      keyPair: credential.identity.getKeyPair(),
      chain: credential.chain && JSON.stringify(credential.chain.toJSON()),
    });
  }

  public async remove(slot: string): Promise<void> {
    const db = await this.#db;
    await db.remove(slot);
  }
}
