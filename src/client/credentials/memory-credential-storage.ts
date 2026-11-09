import { ECDSAKeyIdentity } from '@icp-sdk/core/identity';
import type { Credential, CredentialStorage } from './credential-storage.js';

/**
 * Credentials held for the lifetime of the instance and shared with nothing.
 *
 * For tests and for environments with neither IndexedDB nor `localStorage`. A
 * reload starts from nothing, and other tabs see nothing, so every tab of an
 * origin is alone.
 *
 * Records are handed back as they were given rather than round-tripped through
 * an encoding, which is what lets this hold a non-extractable key at all.
 * @see implements {@link CredentialStorage}
 */
export class MemoryCredentialStorage implements CredentialStorage<ECDSAKeyIdentity> {
  public readonly shared = false;
  public readonly durable = false;

  // On the instance and never on the module: two clients on one page must not
  // see each other's slots, and no state may carry between tests in one process.
  #credentials = new Map<string, Credential<ECDSAKeyIdentity>>();

  public create(): Promise<ECDSAKeyIdentity> {
    // Nothing is serialised here, so the key never has to be readable.
    return ECDSAKeyIdentity.generate({ extractable: false });
  }

  public get(slot: string): Promise<Credential<ECDSAKeyIdentity> | null> {
    return Promise.resolve(this.#credentials.get(slot) ?? null);
  }

  public set(slot: string, credential: Credential<ECDSAKeyIdentity>): Promise<void> {
    this.#credentials.set(slot, credential);
    return Promise.resolve();
  }

  public remove(slot: string): Promise<void> {
    this.#credentials.delete(slot);
    return Promise.resolve();
  }
}
