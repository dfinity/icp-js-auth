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

// localStorage key used to cache the delegation expiration so that
// isAuthenticated() can answer synchronously without hitting IndexedDB.
const KEY_STORAGE_EXPIRATION = 'ic-delegation_expiration';

export type OpenIdProvider = 'google' | 'apple' | 'microsoft';

const OPENID_PROVIDER_URLS: Record<OpenIdProvider, string> = {
  google: 'https://accounts.google.com',
  apple: 'https://appleid.apple.com',
  microsoft: 'https://login.microsoftonline.com/{tid}/v2.0',
};

/**
 * List of options for creating an {@link AuthClient}.
 */
export interface AuthClientCreateOptions {
  /**
   * An {@link SignIdentity} or {@link PartialIdentity} to authenticate via delegation.
   */
  identity?: SignIdentity | PartialIdentity;
  /**
   * Optional storage with get, set, and remove. Uses {@link IdbStorage} by default.
   * @see {@link AuthClientStorage}
   */
  storage?: AuthClientStorage;

  /**
   * Type to use for the base key.
   *
   * If you are using a custom storage provider that does not support CryptoKey storage,
   * you should use `Ed25519` as the key type, as it can serialize to a string.
   * @default 'ECDSA'
   */
  keyType?: BaseKeyType;

  /**
   * Options to handle idle timeouts
   * @default after 10 minutes, invalidates the identity
   */
  idleOptions?: IdleOptions;

  /**
   * Identity provider
   * @default "https://id.ai/authorize"
   */
  identityProvider?: string | URL;

  /**
   * Origin for Identity Provider to use while generating the delegated identity. For II, the derivation origin must authorize this origin by setting a record at `<derivation-origin>/.well-known/ii-alternative-origins`.
   * @see https://github.com/dfinity/internet-identity/blob/main/docs/internet-identity-spec.adoc
   */
  derivationOrigin?: string | URL;

  /**
   * Auth Window feature config string
   * @example "toolbar=0,location=0,menubar=0,width=500,height=500,left=100,top=100"
   */
  windowOpenerFeatures?: string;

  /**
   * OpenID provider for one-click sign-in. When set, the identity provider
   * URL includes an `openid` search param so the user authenticates via
   * the chosen provider (e.g. Google) instead of seeing Internet Identity directly.
   */
  openIdProvider?: OpenIdProvider;
}

export interface IdleOptions extends IdleManagerOptions {
  /**
   * Disables idle functionality for {@link IdleManager}
   * @default false
   */
  disableIdle?: boolean;

  /**
   * Disables default idle behavior - call logout & reload window
   * @default false
   */
  disableDefaultIdleCallback?: boolean;
}

export type OnSuccessFunc = () => void | Promise<void>;

export type OnErrorFunc = (error?: string) => void | Promise<void>;

export interface AuthClientLoginOptions {
  /**
   * Expiration of the authentication in nanoseconds
   * @default  BigInt(8) hours * BigInt(3_600_000_000_000) nanoseconds
   */
  maxTimeToLive?: bigint;
  /**
   * Optional canister targets for the delegation.
   */
  targets?: Principal[];
  /**
   * Callback once login has completed
   */
  onSuccess?: OnSuccessFunc;
  /**
   * Callback in case authentication fails.
   * When provided, errors are passed to this callback instead of being thrown.
   */
  onError?: OnErrorFunc;
}

/**
 * Generates a fresh session key of the given type.
 */
async function generateKey(keyType: BaseKeyType): Promise<SignIdentity> {
  if (keyType === ED25519_KEY_LABEL) {
    return Ed25519KeyIdentity.generate();
  }
  return await ECDSAKeyIdentity.generate();
}

function serializeKey(key: SignIdentity | PartialIdentity): StoredKey {
  if (key instanceof ECDSAKeyIdentity) {
    return key.getKeyPair();
  }
  if (key instanceof Ed25519KeyIdentity) {
    return JSON.stringify(key.toJSON());
  }
  throw new Error('Unsupported key type');
}

/** Serializes and persists a session key to storage. */
async function persistKey(
  storage: AuthClientStorage,
  key: SignIdentity | PartialIdentity,
): Promise<void> {
  const serialized = serializeKey(key);
  await storage.set(KEY_STORAGE_KEY, serialized);
}

/** Loads a session key from storage. Returns `null` when nothing is stored or the value is corrupt. */
async function restoreKey(
  storage: AuthClientStorage,
): Promise<SignIdentity | PartialIdentity | null> {
  const maybeIdentityStorage = await storage.get(KEY_STORAGE_KEY);
  if (!maybeIdentityStorage) return null;

  try {
    // CryptoKeyPair (object) → ECDSA, JSON string → Ed25519
    if (typeof maybeIdentityStorage === 'object') {
      return await ECDSAKeyIdentity.fromKeyPair(maybeIdentityStorage);
    }
    if (typeof maybeIdentityStorage === 'string') {
      return Ed25519KeyIdentity.fromJSON(maybeIdentityStorage);
    }
  } catch {
    // The stored value may be corrupt or from an incompatible version.
    // Returning null lets the caller fall through to key generation,
    // which is safer than crashing on startup.
  }
  return null;
}

async function restoreChain(storage: AuthClientStorage): Promise<DelegationChain | null> {
  const chainStorage = await storage.get(KEY_STORAGE_DELEGATION);
  if (chainStorage === null || chainStorage === undefined) return null;

  if (typeof chainStorage === 'object' && chainStorage !== null) {
    throw new Error(
      'Delegation chain is incorrectly stored. A delegation chain should be stored as a string.',
    );
  }

  return DelegationChain.fromJSON(chainStorage as string);
}

/** Reads the cached delegation expiration from localStorage for synchronous auth checks. */
function getExpirationFlag(): bigint | null {
  try {
    const raw = localStorage.getItem(KEY_STORAGE_EXPIRATION);
    if (!raw) return null;
    return BigInt(raw);
  } catch {
    return null;
  }
}

async function persistChain(storage: AuthClientStorage, chain: DelegationChain): Promise<void> {
  await storage.set(KEY_STORAGE_DELEGATION, JSON.stringify(chain.toJSON()));

  // Write the earliest delegation expiration into localStorage for sync reads.
  const expirations = chain.delegations
    .map((d) => d.delegation.expiration)
    .filter((e): e is bigint => e !== undefined);

  if (expirations.length > 0) {
    const earliest = expirations.reduce((a, b) => (a < b ? a : b));
    try {
      localStorage.setItem(KEY_STORAGE_EXPIRATION, earliest.toString());
    } catch {
      // localStorage may be unavailable – ignore.
    }
  }
}

async function deleteStorage(storage: AuthClientStorage): Promise<void> {
  await storage.remove(KEY_STORAGE_KEY);
  await storage.remove(KEY_STORAGE_DELEGATION);
  await storage.remove(KEY_VECTOR);
  try {
    localStorage.removeItem(KEY_STORAGE_EXPIRATION);
  } catch {
    // localStorage may be unavailable – ignore.
  }
}

/**
 * Migrates a legacy session from localStorage to the primary (IndexedDB) storage.
 * Only applies to ECDSA keys — Ed25519 keys were never stored in localStorage.
 */
async function migrateFromLocalStorage(
  storage: AuthClientStorage,
  keyType: BaseKeyType,
): Promise<void> {
  try {
    const fallbackLocalStorage = new LocalStorage();
    const localChain = await fallbackLocalStorage.get(KEY_STORAGE_DELEGATION);
    const localKey = await fallbackLocalStorage.get(KEY_STORAGE_KEY);
    // not relevant for Ed25519
    if (localChain && localKey && keyType === ECDSA_KEY_LABEL) {
      console.log('Discovered an identity stored in localstorage. Migrating to IndexedDB');
      await storage.set(KEY_STORAGE_DELEGATION, localChain);
      await storage.set(KEY_STORAGE_KEY, localKey);

      // clean up
      await fallbackLocalStorage.remove(KEY_STORAGE_DELEGATION);
      await fallbackLocalStorage.remove(KEY_STORAGE_KEY);
    }
  } catch (error) {
    console.error(`error while attempting to recover localstorage: ${error}`);
  }
}

// ---------------------------------------------------------------------------
// AuthClient
// ---------------------------------------------------------------------------

/**
 * Tool to manage authentication and identity
 * @see {@link AuthClient}
 */
export class AuthClient {
  #identity: Identity | PartialIdentity = new AnonymousIdentity();
  #key: SignIdentity | PartialIdentity | null = null;
  #chain: DelegationChain | null = null;
  #storage: AuthClientStorage;
  #createOptions: AuthClientCreateOptions | undefined;
  #signer: Signer;
  #initPromise: Promise<void>;

  idleManager: IdleManager | undefined;

  /**
   * Create an AuthClient to manage authentication and identity
   * @param {AuthClientCreateOptions} options - Options for creating an {@link AuthClient}
   * @see {@link AuthClientCreateOptions}
   * @param options.identity Optional Identity to use as the base
   * @see {@link SignIdentity}
   * @param options.storage Storage mechanism for delegation credentials
   * @see {@link AuthClientStorage}
   * @param options.keyType Type of key to use for the base key
   * @param {IdleOptions} options.idleOptions Configures an {@link IdleManager}
   * @see {@link IdleOptions}
   * Default behavior is to clear stored identity and reload the page when a user goes idle, unless you set the disableDefaultIdleCallback flag or pass in a custom idle callback.
   * @example
   * const authClient = new AuthClient({
   *   idleOptions: {
   *     disableIdle: true
   *   }
   * })
   */
  constructor(options: AuthClientCreateOptions = {}) {
    this.#storage = options.storage ?? new IdbStorage();
    this.#createOptions = options;

    // Create transport and signer from create-time options so they are reusable across logins.
    const identityProviderUrl = new URL(
      options.identityProvider?.toString() || IDENTITY_PROVIDER_DEFAULT,
    );
    if (options.openIdProvider) {
      identityProviderUrl.searchParams.set('openid', OPENID_PROVIDER_URLS[options.openIdProvider]);
    }

    const transport = new PostMessageTransport({
      url: identityProviderUrl.toString(),
      windowOpenerFeatures: options.windowOpenerFeatures,
    });

    this.#signer = new Signer({
      transport,
      derivationOrigin: options.derivationOrigin?.toString(),
    });

    this.#initPromise = this.#hydrate();
  }

  #init(): Promise<void> {
    return this.#initPromise;
  }

  async #hydrate(): Promise<void> {
    const options = this.#createOptions ?? {};
    const storage = this.#storage;
    const keyType = options.keyType ?? ECDSA_KEY_LABEL;

    let key: SignIdentity | PartialIdentity | null = null;

    if (options.identity) {
      key = options.identity;
    } else {
      key = await restoreKey(storage);

      if (!key) {
        // Attempt to migrate from localstorage
        await migrateFromLocalStorage(storage, keyType);
        key = await restoreKey(storage);
      }
    }

    let chain: DelegationChain | null = null;

    if (key) {
      try {
        if (options.identity) {
          this.#identity = options.identity;
        } else {
          chain = await restoreChain(storage);
          if (chain) {
            if (!isDelegationValid(chain)) {
              await deleteStorage(storage);
              key = null;
            } else {
              if ('toDer' in key) {
                this.#identity = PartialDelegationIdentity.fromDelegation(key, chain);
              } else {
                this.#identity = DelegationIdentity.fromDelegation(key, chain);
              }
            }
          }
        }
      } catch (e) {
        console.error(e);
        await deleteStorage(storage);
        key = null;
      }
    }

    // Idle manager setup
    if (options.idleOptions?.disableIdle) {
      this.idleManager = undefined;
    } else if (chain || options.identity) {
      this.idleManager = IdleManager.create(options.idleOptions);
    }

    if (!key) {
      if (keyType === ED25519_KEY_LABEL) {
        key = Ed25519KeyIdentity.generate();
      } else {
        if (options.storage && keyType === ECDSA_KEY_LABEL) {
          console.warn(
            `You are using a custom storage provider that may not support CryptoKey storage. If you are using a custom storage provider that does not support CryptoKey storage, you should use '${ED25519_KEY_LABEL}' as the key type, as it can serialize to a string`,
          );
        }
        key = await ECDSAKeyIdentity.generate();
      }
      await persistKey(storage, key);
    }

    this.#key = key;
    this.#chain = chain;

    this.#registerDefaultIdleCallback();
  }

  #registerDefaultIdleCallback() {
    const idleOptions = this.#createOptions?.idleOptions;
    /**
     * Default behavior is to clear stored identity and reload the page.
     * By either setting the disableDefaultIdleCallback flag or passing in a custom idle callback, we will ignore this config
     */
    if (!idleOptions?.onIdle && !idleOptions?.disableDefaultIdleCallback) {
      this.idleManager?.registerCallback(() => {
        this.logout();
        location.reload();
      });
    }
  }

  async getIdentity(): Promise<Identity> {
    await this.#init();
    return this.#identity;
  }

  isAuthenticated(): boolean {
    const expiration = getExpirationFlag();
    if (expiration === null) return false;
    const nowNanos = BigInt(Date.now()) * BigInt(1_000_000);
    return expiration > nowNanos;
  }

  /**
   * AuthClient Login - Opens up a new window to authenticate with Internet Identity
   *
   * Generates a fresh session key for every login attempt. If `onError` is provided,
   * errors are routed to that callback; otherwise login() throws on failure.
   *
   * @param {AuthClientLoginOptions} options - Per-login options (maxTimeToLive, targets, callbacks).
   * @param options.maxTimeToLive Expiration of the authentication in nanoseconds
   * @param options.onSuccess Callback once login has completed
   * @param options.onError Callback in case authentication fails
   * @example
   * const authClient = new AuthClient({
   *  identityProvider: 'http://<canisterID>.127.0.0.1:8000',
   *  windowOpenerFeatures: "toolbar=0,location=0,menubar=0,width=500,height=500,left=100,top=100",
   * });
   * authClient.login({
   *  maxTimeToLive: BigInt (7) * BigInt(24) * BigInt(3_600_000_000_000), // 1 week
   *  onSuccess: () => {
   *    console.log('Login Successful!');
   *  },
   *  onError: (error) => {
   *    console.error('Login Failed: ', error);
   *  }
   * });
   */
  async login(options?: AuthClientLoginOptions): Promise<void> {
    // Set default maxTimeToLive to 8 hours
    const maxTimeToLive = options?.maxTimeToLive ?? DEFAULT_MAX_TIME_TO_LIVE;

    try {
      // Generate a fresh session key for every login attempt instead of reusing the stored one.
      const key =
        this.#createOptions?.identity ??
        (await generateKey(this.#createOptions?.keyType ?? ECDSA_KEY_LABEL));

      const delegationChain = await this.#signer.requestDelegation({
        publicKey: key.getPublicKey(),
        targets: options?.targets,
        maxTimeToLive,
      });

      // Store the new session state and set up idle tracking.
      this.#key = key;
      this.#chain = delegationChain;

      if ('toDer' in key) {
        this.#identity = PartialDelegationIdentity.fromDelegation(key, this.#chain);
      } else {
        this.#identity = DelegationIdentity.fromDelegation(key, this.#chain);
      }

      const idleOptions = this.#createOptions?.idleOptions;
      if (!this.idleManager && !idleOptions?.disableIdle) {
        this.idleManager = IdleManager.create(idleOptions);
        this.#registerDefaultIdleCallback();
      }

      if (this.#chain) {
        await persistChain(this.#storage, this.#chain);
      }

      // Persist the fresh key that was used for this login.
      await persistKey(this.#storage, this.#key);

      // Call onSuccess last: the callback may navigate away or reload the
      // page, so all session state must be persisted before it runs.
      await options?.onSuccess?.();
    } catch (err) {
      // If an onError callback is provided, route the error there (callback-style).
      // Otherwise, re-throw so callers can use try/catch or .catch().
      if (options?.onError) {
        await options.onError((err as Error).message);
      } else {
        throw err;
      }
    } finally {
      await this.#signer.closeChannel();
    }
  }

  async logout(options: { returnTo?: string } = {}): Promise<void> {
    await deleteStorage(this.#storage);

    // Reset this auth client to a non-authenticated state.
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
}
