import { AnonymousIdentity, type Identity, type SignIdentity } from '@icp-sdk/core/agent';
import {
  DelegationChain,
  DelegationIdentity,
  ECDSAKeyIdentity,
  Ed25519KeyIdentity,
  isDelegationValid,
  PartialDelegationIdentity,
  type PartialIdentity,
} from '@icp-sdk/core/identity';
import type { Principal } from '@icp-sdk/core/principal';
import { Signer } from '@icp-sdk/signer';
import { PostMessageTransport } from '@icp-sdk/signer/web';
import { IdleManager, type IdleManagerOptions } from './idle-manager.js';
import {
  type AuthClientStorage,
  IdbStorage,
  KEY_STORAGE_DELEGATION,
  KEY_STORAGE_KEY,
  KEY_VECTOR,
  LocalStorage,
  type StoredKey,
} from './storage.js';

const NANOSECONDS_PER_SECOND = BigInt(1_000_000_000);
const SECONDS_PER_HOUR = BigInt(3_600);
const NANOSECONDS_PER_HOUR = NANOSECONDS_PER_SECOND * SECONDS_PER_HOUR;

const IDENTITY_PROVIDER_DEFAULT = 'https://id.ai/authorize';
const DEFAULT_MAX_TIME_TO_LIVE = BigInt(8) * NANOSECONDS_PER_HOUR;

const ECDSA_KEY_LABEL = 'ECDSA';
const ED25519_KEY_LABEL = 'Ed25519';
type BaseKeyType = typeof ECDSA_KEY_LABEL | typeof ED25519_KEY_LABEL;

const KEY_STORAGE_EXPIRATION = 'ic-delegation_expiration';

export const ERROR_USER_INTERRUPT = 'UserInterrupt';

/**
 * Options for creating an {@link AuthClient}.
 */
export interface AuthClientCreateOptions {
  /**
   * An identity to authenticate via delegation.
   */
  identity?: SignIdentity | PartialIdentity;

  /**
   * Persistent storage backend. Defaults to IndexedDB.
   * @default IdbStorage
   */
  storage?: AuthClientStorage;

  /**
   * Type of session key to generate on each login.
   *
   * Use `'Ed25519'` when your storage provider does not support `CryptoKey`.
   * @default 'ECDSA'
   */
  keyType?: BaseKeyType;

  /**
   * Idle timeout configuration.
   * @default after 10 minutes, invalidates the identity
   */
  idleOptions?: IdleOptions;

  /**
   * Identity provider URL.
   * @default "https://id.ai/authorize"
   */
  identityProvider?: string | URL;

  /**
   * Derivation origin for the identity provider.
   * @see https://github.com/dfinity/internet-identity/blob/main/docs/internet-identity-spec.adoc
   */
  derivationOrigin?: string | URL;

  /**
   * Window features string for the authentication popup.
   * @example "toolbar=0,location=0,menubar=0,width=500,height=500,left=100,top=100"
   */
  windowOpenerFeatures?: string;
}

export interface IdleOptions extends IdleManagerOptions {
  /**
   * Disables idle functionality entirely.
   * @default false
   */
  disableIdle?: boolean;

  /**
   * Disables the default idle callback (logout & reload).
   * @default false
   */
  disableDefaultIdleCallback?: boolean;
}

export type OnSuccessFunc = (() => void | Promise<void>) | (() => void | Promise<void>);

export type OnErrorFunc = (error?: string) => void | Promise<void>;

/**
 * Options for {@link AuthClient.login}.
 */
export interface AuthClientLoginOptions {
  /**
   * Maximum lifetime of the delegation in nanoseconds.
   * @default 8 hours
   */
  maxTimeToLive?: bigint;

  /**
   * Restrict the delegation to specific canisters.
   */
  targets?: Principal[];

  /**
   * Called after a successful login.
   */
  onSuccess?: OnSuccessFunc;

  /**
   * Called when login fails. When provided the error is **not** re-thrown,
   * allowing the caller to handle it via this callback instead.
   */
  onError?: OnErrorFunc;
}

/**
 * Manages authentication and identity for Internet Computer web apps.
 *
 * @example
 * const authClient = new AuthClient();
 *
 * if (authClient.isAuthenticated()) {
 *   const identity = await authClient.getIdentity();
 * }
 *
 * await authClient.login({
 *   onSuccess: () => console.log('Logged in!'),
 * });
 */
export class AuthClient {
  #identity: Identity | PartialIdentity = new AnonymousIdentity();
  #chain: DelegationChain | null = null;
  #storage: AuthClientStorage;
  #signer: Signer;
  #options: AuthClientCreateOptions;
  #initPromise: Promise<void> | null = null;
  idleManager: IdleManager | undefined;

  constructor(options: AuthClientCreateOptions = {}) {
    this.#options = options;
    this.#storage = options.storage ?? new IdbStorage();

    const identityProviderUrl = options.identityProvider?.toString() || IDENTITY_PROVIDER_DEFAULT;

    const transport = new PostMessageTransport({
      url: identityProviderUrl,
      windowOpenerFeatures: options.windowOpenerFeatures,
    });

    this.#signer = new Signer({
      transport,
      derivationOrigin: options.derivationOrigin?.toString(),
    });

    this.#registerDefaultIdleCallback();

    // Eagerly start restoring a previous session from storage.
    // The result is awaited in getIdentity() before returning.
    this.#init();
  }

  /**
   * Returns the current identity, restoring a previous session if available.
   */
  async getIdentity(): Promise<Identity> {
    await this.#init();
    return this.#identity;
  }

  /**
   * Checks whether the user has an active, non-expired session.
   */
  isAuthenticated(): boolean {
    // Uses a cached expiration in localStorage to avoid an async IndexedDB read.
    const expiration = getExpirationFlag();
    if (expiration === null) return false;
    const nowNs = BigInt(Date.now()) * BigInt(1_000_000);
    return nowNs < expiration;
  }

  /**
   * Opens the identity provider and requests a delegation.
   *
   * @param options - Login options.
   * @param options.maxTimeToLive - Maximum lifetime of the delegation in nanoseconds.
   * @param options.targets - Restrict the delegation to specific canisters.
   * @param options.onSuccess - Called after a successful login.
   * @param options.onError - Called when login fails. When provided the error is not re-thrown.
   * @throws When authentication fails and no `onError` callback is provided.
   *
   * @example
   * await authClient.login({
   *   onSuccess: () => console.log('Logged in!'),
   *   onError: (err) => console.error(err),
   * });
   */
  async login(options?: AuthClientLoginOptions): Promise<void> {
    try {
      await this.#signer.openChannel();

      const maxTimeToLive = options?.maxTimeToLive ?? DEFAULT_MAX_TIME_TO_LIVE;

      // Fresh key per login so each session has its own cryptographic identity.
      const key =
        this.#options.identity ?? (await generateKey(this.#options.keyType ?? ECDSA_KEY_LABEL));

      const delegationChain = await this.#signer.requestDelegation({
        publicKey: key.getPublicKey(),
        targets: options?.targets,
        maxTimeToLive,
      });

      this.#chain = delegationChain;

      // PartialIdentity only has the public key — no signing capability.
      if ('toDer' in key) {
        this.#identity = PartialDelegationIdentity.fromDelegation(key, this.#chain);
      } else {
        this.#identity = DelegationIdentity.fromDelegation(key, this.#chain);
      }

      const idleOptions = this.#options?.idleOptions;
      if (!this.idleManager && !idleOptions?.disableIdle) {
        this.idleManager = IdleManager.create(idleOptions);
        this.#registerDefaultIdleCallback();
      }

      // Persist so the session survives page reloads.
      await persistChain(this.#storage, this.#chain);
      await persistKey(this.#storage, key);

      options?.onSuccess?.();
    } catch (error) {
      // If an onError callback is provided, delegate error handling to the caller.
      // Otherwise, re-throw so the error can be caught with try/catch or .catch().
      if (options?.onError) {
        options.onError(error instanceof Error ? error.message : String(error));
      } else {
        throw error;
      }
    }
  }

  /**
   * Clears the stored session and resets the client to an anonymous state.
   *
   * @param options - Logout options.
   * @param options.returnTo - URL to navigate to after logout.
   */
  async logout(options: { returnTo?: string } = {}): Promise<void> {
    await deleteStorage(this.#storage);

    this.#identity = new AnonymousIdentity();
    this.#chain = null;

    if (options.returnTo) {
      try {
        window.history.pushState({}, '', options.returnTo);
      } catch {
        window.location.href = options.returnTo;
      }
    }
  }

  // Memoized — only runs #hydrate once, returns the same promise on repeat calls.
  #init(): Promise<void> {
    if (!this.#initPromise) {
      this.#initPromise = this.#hydrate();
    }
    return this.#initPromise;
  }

  // Attempts to restore a previous session (key + delegation chain) from
  // storage. If found and still valid, sets #identity and #chain so the
  // client is ready to use without a new login().
  async #hydrate(): Promise<void> {
    const key =
      this.#options.identity ??
      (await restoreKey(this.#storage, this.#options.keyType ?? ECDSA_KEY_LABEL));
    if (!key) return;

    const chain = await restoreChain(this.#storage);
    if (!chain) return;

    this.#chain = chain;
    if ('toDer' in key) {
      this.#identity = PartialDelegationIdentity.fromDelegation(key, chain);
    } else {
      this.#identity = DelegationIdentity.fromDelegation(key, chain);
    }

    if (!this.#options.idleOptions?.disableIdle && !this.idleManager) {
      this.idleManager = IdleManager.create(this.#options.idleOptions);
      this.#registerDefaultIdleCallback();
    }
  }

  #registerDefaultIdleCallback() {
    const idleOptions = this.#options?.idleOptions;
    if (!idleOptions?.onIdle && !idleOptions?.disableDefaultIdleCallback) {
      this.idleManager?.registerCallback(() => {
        this.logout();
        location.reload();
      });
    }
  }
}

/**
 * Generates a new session key.
 * @param keyType - The key algorithm to use.
 */
async function generateKey(keyType: BaseKeyType): Promise<SignIdentity> {
  if (keyType === ED25519_KEY_LABEL) {
    return Ed25519KeyIdentity.generate();
  }
  return await ECDSAKeyIdentity.generate();
}

/**
 * Saves a session key to storage.
 * @param storage - The storage backend.
 * @param key - The key to persist.
 */
async function persistKey(
  storage: AuthClientStorage,
  key: SignIdentity | PartialIdentity,
): Promise<void> {
  await storage.set(KEY_STORAGE_KEY, serializeKey(key));
}

/**
 * Loads a session key from storage. Falls back to migrating a legacy
 * key from localStorage if nothing is found in the primary store.
 * @param storage - The storage backend.
 * @param keyType - The expected key algorithm (determines deserialization).
 */
async function restoreKey(
  storage: AuthClientStorage,
  keyType: BaseKeyType,
): Promise<SignIdentity | PartialIdentity | null> {
  let stored = await storage.get(KEY_STORAGE_KEY);
  if (!stored) {
    stored = await migrateFromLocalStorage(storage, keyType);
  }
  if (!stored) return null;

  try {
    // CryptoKeyPair (object) → ECDSA, JSON string → Ed25519
    if (typeof stored === 'object') {
      return await ECDSAKeyIdentity.fromKeyPair(stored);
    }
    return Ed25519KeyIdentity.fromJSON(stored);
  } catch {
    return null;
  }
}

/**
 * Converts a key into a format suitable for storage.
 * @param key - The key to serialize.
 */
function serializeKey(key: SignIdentity | PartialIdentity): StoredKey {
  if (key instanceof ECDSAKeyIdentity) return key.getKeyPair();
  if (key instanceof Ed25519KeyIdentity) return JSON.stringify(key.toJSON());
  throw new Error('Unsupported key type');
}

/**
 * Saves the delegation chain and caches its earliest expiration
 * in localStorage so {@link AuthClient.isAuthenticated} can check it synchronously.
 * @param storage - The storage backend.
 * @param chain - The delegation chain to persist.
 */
async function persistChain(storage: AuthClientStorage, chain: DelegationChain): Promise<void> {
  await storage.set(KEY_STORAGE_DELEGATION, JSON.stringify(chain.toJSON()));

  let earliest: bigint | null = null;
  for (const { delegation } of chain.delegations) {
    if (earliest === null || delegation.expiration < earliest) {
      earliest = delegation.expiration;
    }
  }
  if (earliest !== null) {
    localStorage.setItem(KEY_STORAGE_EXPIRATION, earliest.toString());
  }
}

/**
 * Loads the delegation chain from storage. Returns `null` and wipes
 * storage if the chain is expired or corrupted.
 * @param storage - The storage backend.
 */
async function restoreChain(storage: AuthClientStorage): Promise<DelegationChain | null> {
  try {
    const raw = await storage.get(KEY_STORAGE_DELEGATION);
    if (!raw || typeof raw !== 'string') return null;

    const chain = DelegationChain.fromJSON(raw);
    if (!isDelegationValid(chain)) {
      await deleteStorage(storage);
      return null;
    }
    return chain;
  } catch (e) {
    console.error(e);
    await deleteStorage(storage);
    return null;
  }
}

/**
 * Clears all session data from storage.
 * @param storage - The storage backend.
 */
async function deleteStorage(storage: AuthClientStorage): Promise<void> {
  await storage.remove(KEY_STORAGE_KEY);
  await storage.remove(KEY_STORAGE_DELEGATION);
  await storage.remove(KEY_VECTOR);
  localStorage.removeItem(KEY_STORAGE_EXPIRATION);
}

/** Reads the cached delegation expiration from localStorage (nanoseconds). */
function getExpirationFlag(): bigint | null {
  const value = localStorage.getItem(KEY_STORAGE_EXPIRATION);
  if (value === null) return null;
  return BigInt(value);
}

/**
 * One-time migration: moves a legacy session stored in localStorage
 * into the primary storage, then cleans up the old entries.
 * @param storage - The target storage backend.
 * @param keyType - The expected key algorithm (only ECDSA keys are migrated).
 */
async function migrateFromLocalStorage(
  storage: AuthClientStorage,
  keyType: BaseKeyType,
): Promise<StoredKey | null> {
  try {
    const fallback = new LocalStorage();
    const localChain = await fallback.get(KEY_STORAGE_DELEGATION);
    const localKey = await fallback.get(KEY_STORAGE_KEY);

    if (!localChain || !localKey || keyType !== ECDSA_KEY_LABEL) return null;

    console.log('Discovered an identity stored in localstorage. Migrating to IndexedDB');
    await storage.set(KEY_STORAGE_DELEGATION, localChain);
    await storage.set(KEY_STORAGE_KEY, localKey);
    await fallback.remove(KEY_STORAGE_DELEGATION);
    await fallback.remove(KEY_STORAGE_KEY);

    return localKey;
  } catch (error) {
    console.error(`error while attempting to recover localstorage: ${error}`);
    return null;
  }
}
