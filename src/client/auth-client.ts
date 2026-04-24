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

export const OPENID_PROVIDER_URLS = {
  google: 'https://accounts.google.com',
  apple: 'https://appleid.apple.com',
  microsoft: 'https://login.microsoftonline.com/{tid}/v2.0',
} as const satisfies Record<OpenIdProvider, string>;

const DEFAULT_OPENID_SCOPE_KEYS = ['name', 'email', 'verified_email'] as const;

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
   * Type of session key to generate on each sign-in.
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

  /**
   * OpenID provider for one-click sign-in. When set, the identity provider
   * URL includes an `openid` search param so the user authenticates via
   * the chosen provider (e.g. Google) instead of seeing Internet Identity directly.
   */
  openIdProvider?: OpenIdProvider;
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

/**
 * Options for {@link AuthClient.signIn}.
 */
export interface AuthClientSignInOptions {
  /**
   * Maximum lifetime of the delegation in nanoseconds.
   * @default 8 hours
   */
  maxTimeToLive?: bigint;

  /**
   * Restrict the delegation to specific canisters.
   */
  targets?: Principal[];
}

export interface SignedAttributes {
  data: Uint8Array;
  signature: Uint8Array;
}

/**
 * Manages authentication and identity for Internet Computer web apps.
 *
 * @example
 * const authClient = new AuthClient();
 *
 * const identity = authClient.isAuthenticated()
 *   ? await authClient.getIdentity()
 *   : await authClient.signIn();
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
   * Opens the identity provider, requests a delegation, and returns the authenticated identity.
   *
   * @param options - Sign-in options.
   * @param options.maxTimeToLive - Maximum lifetime of the delegation in nanoseconds.
   * @param options.targets - Restrict the delegation to specific canisters.
   * @returns The authenticated identity.
   * @throws When authentication fails.
   *
   * @example
   * try {
   *   const identity = await authClient.signIn();
   * } catch (error) {
   *   console.error('Sign-in failed:', error);
   * }
   */
  async signIn(options?: AuthClientSignInOptions): Promise<Identity> {
    await this.#signer.openChannel();

    const maxTimeToLive = options?.maxTimeToLive ?? DEFAULT_MAX_TIME_TO_LIVE;

    // Fresh key per sign-in so each session has its own cryptographic identity.
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

    return this.#identity;
  }

  /**
   * Requests signed identity attributes from the identity provider.
   *
   * @param params - Request parameters.
   * @param params.keys - Attribute keys to request (e.g. `['email', 'name']`).
   * @param params.nonce - 32-byte nonce issued by the RP canister.
   * @returns Signed attribute data and signature.
   * @throws When the identity provider returns an error or an invalid response.
   */
  async requestAttributes(params: {
    keys: string[];
    nonce: Uint8Array;
  }): Promise<SignedAttributes> {
    const nonceBytes = params.nonce;

    const response = await this.#signer.sendRequest({
      jsonrpc: '2.0',
      id: globalThis.crypto.randomUUID(),
      method: 'ii-icrc3-attributes',
      params: { keys: params.keys, nonce: toBase64(nonceBytes) },
    });

    if ('error' in response) {
      throw new Error(response.error.message);
    }

    const result = response.result as Record<string, unknown> | undefined;
    if (typeof result?.data !== 'string' || typeof result?.signature !== 'string') {
      throw new Error('Invalid response: missing data or signature');
    }

    try {
      return {
        data: fromBase64(result.data),
        signature: fromBase64(result.signature),
      };
    } catch (cause) {
      throw new Error('Invalid response: data or signature is not valid base64', { cause });
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
  // client is ready to use without a new signIn().
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
 * Encodes a Uint8Array to a base64 string.
 * @param bytes - The bytes to encode.
 */
function toBase64(bytes: Uint8Array): string {
  if ('toBase64' in bytes && typeof bytes.toBase64 === 'function') {
    return bytes.toBase64();
  }
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return globalThis.btoa(binary);
}

/**
 * Decodes a base64 string to a Uint8Array.
 * @param str - The base64-encoded string.
 */
function fromBase64(str: string): Uint8Array {
  if ('fromBase64' in Uint8Array && typeof Uint8Array.fromBase64 === 'function') {
    return Uint8Array.fromBase64(str);
  }
  const binary = globalThis.atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
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
    // The stored value may be corrupt or from an incompatible version.
    // Returning null lets the caller fall through to key generation,
    // which is safer than crashing on startup.
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

/**
 * Scopes attribute keys to an OpenID provider.
 *
 * When using one-click sign-in, attributes can be scoped to the same provider
 * so the user grants access in a single step without an additional prompt.
 *
 * @param params.openIdProvider - The OpenID provider the keys should be scoped to.
 * @param params.keys - The attribute keys to scope. Defaults to `['name', 'email', 'verified_email']`.
 * @returns The scoped attribute keys as `openid:<provider-url>:<key>`.
 *
 * @example
 * scopedKeys({ openIdProvider: 'google', keys: ['email'] });
 * // ['openid:https://accounts.google.com:email']
 */
export function scopedKeys<
  P extends keyof typeof OPENID_PROVIDER_URLS,
  K extends string = (typeof DEFAULT_OPENID_SCOPE_KEYS)[number],
>(params: {
  openIdProvider: P;
  keys?: readonly K[];
}): `openid:${(typeof OPENID_PROVIDER_URLS)[P]}:${K}`[] {
  const provider = OPENID_PROVIDER_URLS[params.openIdProvider];
  const keys = params.keys ?? DEFAULT_OPENID_SCOPE_KEYS;
  return keys.map(
    (key) => `openid:${provider}:${key}` as `openid:${(typeof OPENID_PROVIDER_URLS)[P]}:${K}`,
  );
}
