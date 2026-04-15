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

/**
 * Tool to manage authentication and identity
 * @see {@link AuthClient}
 */
export class AuthClient {
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
   * const authClient = await AuthClient.create({
   *   idleOptions: {
   *     disableIdle: true
   *   }
   * })
   */
  public static async create(options: AuthClientCreateOptions = {}): Promise<AuthClient> {
    const storage = options.storage ?? new IdbStorage();
    const keyType = options.keyType ?? ECDSA_KEY_LABEL;

    let key: null | SignIdentity | PartialIdentity = null;
    if (options.identity) {
      key = options.identity;
    } else {
      let maybeIdentityStorage = await storage.get(KEY_STORAGE_KEY);
      if (!maybeIdentityStorage) {
        // Attempt to migrate from localstorage
        try {
          const fallbackLocalStorage = new LocalStorage();
          const localChain = await fallbackLocalStorage.get(KEY_STORAGE_DELEGATION);
          const localKey = await fallbackLocalStorage.get(KEY_STORAGE_KEY);
          // not relevant for Ed25519
          if (localChain && localKey && keyType === ECDSA_KEY_LABEL) {
            console.log('Discovered an identity stored in localstorage. Migrating to IndexedDB');
            await storage.set(KEY_STORAGE_DELEGATION, localChain);
            await storage.set(KEY_STORAGE_KEY, localKey);

            maybeIdentityStorage = localChain;
            // clean up
            await fallbackLocalStorage.remove(KEY_STORAGE_DELEGATION);
            await fallbackLocalStorage.remove(KEY_STORAGE_KEY);
          }
        } catch (error) {
          console.error(`error while attempting to recover localstorage: ${error}`);
        }
      }
      if (maybeIdentityStorage) {
        try {
          if (typeof maybeIdentityStorage === 'object') {
            if (keyType === ED25519_KEY_LABEL && typeof maybeIdentityStorage === 'string') {
              key = Ed25519KeyIdentity.fromJSON(maybeIdentityStorage);
            } else {
              key = await ECDSAKeyIdentity.fromKeyPair(maybeIdentityStorage);
            }
          } else if (typeof maybeIdentityStorage === 'string') {
            // This is a legacy identity, which is a serialized Ed25519KeyIdentity.
            key = Ed25519KeyIdentity.fromJSON(maybeIdentityStorage);
          }
        } catch {
          // Ignore this, this means that the localStorage value isn't a valid Ed25519KeyIdentity or ECDSAKeyIdentity
          // serialization.
        }
      }
    }

    let identity: SignIdentity | PartialIdentity = new AnonymousIdentity() as PartialIdentity;
    let chain: null | DelegationChain = null;
    if (key) {
      try {
        const chainStorage = await storage.get(KEY_STORAGE_DELEGATION);
        if (typeof chainStorage === 'object' && chainStorage !== null) {
          throw new Error(
            'Delegation chain is incorrectly stored. A delegation chain should be stored as a string.',
          );
        }

        if (options.identity) {
          identity = options.identity;
        } else if (chainStorage) {
          chain = DelegationChain.fromJSON(chainStorage);

          // Verify that the delegation isn't expired.
          if (!isDelegationValid(chain)) {
            await _deleteStorage(storage);
            key = null;
          } else {
            // If the key is a public key, then we create a PartialDelegationIdentity.
            if ('toDer' in key) {
              identity = PartialDelegationIdentity.fromDelegation(key, chain);
              // otherwise, we create a DelegationIdentity.
            } else {
              identity = DelegationIdentity.fromDelegation(key, chain);
            }
          }
        }
      } catch (e) {
        console.error(e);
        // If there was a problem loading the chain, delete the key.
        await _deleteStorage(storage);
        key = null;
      }
    }
    let idleManager: IdleManager | undefined;
    if (options.idleOptions?.disableIdle) {
      idleManager = undefined;
    }
    // if there is a delegation chain or provided identity, setup idleManager
    else if (chain || options.identity) {
      idleManager = IdleManager.create(options.idleOptions);
    }

    if (!key) {
      // Create a new key (whether or not one was in storage).
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

    // Create transport and signer from create-time options so they are reusable across logins.
    const identityProviderUrl = options.identityProvider?.toString() || IDENTITY_PROVIDER_DEFAULT;

    const transport = new PostMessageTransport({
      url: identityProviderUrl,
      windowOpenerFeatures: options.windowOpenerFeatures,
    });

    const signer = new Signer({
      transport,
      derivationOrigin: options.derivationOrigin?.toString(),
    });

    return new AuthClient(identity, key, chain, storage, idleManager, options, signer);
  }

  protected constructor(
    private _identity: Identity | PartialIdentity,
    private _key: SignIdentity | PartialIdentity,
    private _chain: DelegationChain | null,
    private _storage: AuthClientStorage,
    public idleManager: IdleManager | undefined,
    private _createOptions: AuthClientCreateOptions | undefined,
    private _signer: Signer,
  ) {
    this._registerDefaultIdleCallback();
  }

  private _registerDefaultIdleCallback() {
    const idleOptions = this._createOptions?.idleOptions;
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

  private async _handleSuccess(
    key: SignIdentity | PartialIdentity,
    delegationChain: DelegationChain,
    onSuccess?: OnSuccessFunc,
  ) {
    if (!key) {
      return;
    }

    this._key = key;
    this._chain = delegationChain;

    if ('toDer' in key) {
      this._identity = PartialDelegationIdentity.fromDelegation(key, this._chain);
    } else {
      this._identity = DelegationIdentity.fromDelegation(key, this._chain);
    }

    const idleOptions = this._createOptions?.idleOptions;
    // create the idle manager on a successful login if we haven't disabled it
    // and it doesn't already exist.
    if (!this.idleManager && !idleOptions?.disableIdle) {
      this.idleManager = IdleManager.create(idleOptions);
      this._registerDefaultIdleCallback();
    }

    if (this._chain) {
      await this._storage.set(KEY_STORAGE_DELEGATION, JSON.stringify(this._chain.toJSON()));
    }

    // Persist the fresh key that was used for this login.
    await persistKey(this._storage, this._key);

    // onSuccess should be the last thing to do to avoid consumers
    // interfering by navigating or refreshing the page
    await onSuccess?.();
  }

  public getIdentity(): Identity {
    return this._identity;
  }

  public async isAuthenticated(): Promise<boolean> {
    return (
      !this.getIdentity().getPrincipal().isAnonymous() &&
      this._chain !== null &&
      isDelegationValid(this._chain)
    );
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
   * const authClient = await AuthClient.create({
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
  public async login(options?: AuthClientLoginOptions): Promise<void> {
    // Set default maxTimeToLive to 8 hours
    const maxTimeToLive = options?.maxTimeToLive ?? DEFAULT_MAX_TIME_TO_LIVE;

    try {
      await this._signer.openChannel();

      // Generate a fresh session key for every login attempt instead of reusing the stored one.
      const key =
        this._createOptions?.identity ??
        (await generateKey(this._createOptions?.keyType ?? ECDSA_KEY_LABEL));

      const delegationChain = await this._signer.requestDelegation({
        publicKey: key.getPublicKey(),
        targets: options?.targets,
        maxTimeToLive,
      });

      await this._handleSuccess(key, delegationChain, options?.onSuccess);
    } catch (err) {
      // If an onError callback is provided, route the error there (callback-style).
      // Otherwise, re-throw so callers can use try/catch or .catch().
      if (options?.onError) {
        await options.onError((err as Error).message);
      } else {
        throw err;
      }
    } finally {
      await this._signer.closeChannel();
    }
  }

  public async logout(options: { returnTo?: string } = {}): Promise<void> {
    await _deleteStorage(this._storage);

    // Reset this auth client to a non-authenticated state.
    this._identity = new AnonymousIdentity();
    this._chain = null;

    if (options.returnTo) {
      try {
        window.history.pushState({}, '', options.returnTo);
      } catch {
        window.location.href = options.returnTo;
      }
    }
  }
}

async function _deleteStorage(storage: AuthClientStorage) {
  await storage.remove(KEY_STORAGE_KEY);
  await storage.remove(KEY_STORAGE_DELEGATION);
  await storage.remove(KEY_VECTOR);
}

function toStoredKey(key: SignIdentity | PartialIdentity): StoredKey {
  if (key instanceof ECDSAKeyIdentity) {
    return key.getKeyPair();
  }
  if (key instanceof Ed25519KeyIdentity) {
    return JSON.stringify(key.toJSON());
  }
  throw new Error('Unsupported key type');
}

async function persistKey(
  storage: AuthClientStorage,
  key: SignIdentity | PartialIdentity,
): Promise<void> {
  const serialized = toStoredKey(key);
  await storage.set(KEY_STORAGE_KEY, serialized);
}
