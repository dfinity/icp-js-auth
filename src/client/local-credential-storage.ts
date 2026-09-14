import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import type { Credential, CredentialStorage } from './credential-storage.js';

/** What one slot holds: the key as JSON, and the chain as JSON. */
interface StoredCredential {
  key: string;
  chain?: string;
}

/**
 * Credentials in `localStorage`, for where IndexedDB is unavailable.
 *
 * `localStorage` holds strings, so the key has to be one: this generates an
 * Ed25519 identity, whose private bytes serialise, rather than the
 * non-extractable key {@link IdbCredentialStorage} uses. That is the trade the
 * medium imposes, and it is why generation belongs to the store.
 * @see implements {@link CredentialStorage}
 */
export class LocalCredentialStorage implements CredentialStorage<Ed25519KeyIdentity> {
  public readonly shared = true;
  public readonly durable = true;

  /**
   * @param prefix - Prepended to every slot, so two clients under one origin can
   *   be kept apart.
   */
  constructor(public readonly prefix = 'ic-') {}

  public create(): Promise<Ed25519KeyIdentity> {
    return Promise.resolve(Ed25519KeyIdentity.generate());
  }

  public get(slot: string): Promise<Credential<Ed25519KeyIdentity> | null> {
    const raw = this.#localStorage().getItem(this.prefix + slot);
    if (raw === null) return Promise.resolve(null);

    try {
      const stored = JSON.parse(raw) as StoredCredential;
      const identity = Ed25519KeyIdentity.fromJSON(stored.key);
      const chain = stored.chain === undefined ? undefined : DelegationChain.fromJSON(stored.chain);
      return Promise.resolve({ identity, chain });
    } catch {
      return Promise.resolve(null);
    }
  }

  public set(slot: string, credential: Credential<Ed25519KeyIdentity>): Promise<void> {
    const stored: StoredCredential = {
      key: JSON.stringify(credential.identity.toJSON()),
      chain: credential.chain && JSON.stringify(credential.chain.toJSON()),
    };
    this.#localStorage().setItem(this.prefix + slot, JSON.stringify(stored));
    return Promise.resolve();
  }

  public remove(slot: string): Promise<void> {
    this.#localStorage().removeItem(this.prefix + slot);
    return Promise.resolve();
  }

  #localStorage(): Storage {
    const ls = globalThis.localStorage;
    if (!ls) {
      throw new Error('Could not find local storage.');
    }
    return ls;
  }
}
