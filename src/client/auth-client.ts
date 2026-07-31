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
import { PostMessageTransport, UrlTransport } from '@icp-sdk/signer/web';
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

// Storage key prefix for a redirect flow's session key, held only while the
// flow is in progress (keyed by a per-flow id) and removed once the delegation
// is persisted. See AuthClient.#acquireSessionKey.
const PENDING_KEY_PREFIX = 'ic-auth-pending-key:';

// The storage backend has no key enumeration, so pending-key slots are tracked
// explicitly here: an abandoned flow never removes its key, so a later flow
// prunes expired orphans by slot instead of leaking them forever.
const PENDING_KEYS_REGISTRY_KEY = 'ic-auth-pending-keys';
// Past the URL transport's ~10-min flow window the flow can't resume, so a
// pending key older than this is treated as abandoned.
const PENDING_KEY_TTL_MS = 10 * 60 * 1000;

interface PendingKeyEntry {
  slot: string;
  expiresAt: number;
}

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
   * How the client communicates with the identity provider.
   *
   * - `'window'` (default) — the identity provider opens in a separate browser
   *   tab or window (a popup when {@link windowOpenerFeatures} is set) and
   *   communicates over the ICRC-29 `postMessage` transport.
   * - `'redirect'` — the current page navigates to the identity provider over
   *   the ICRC-167 URL transport, which returns to this same page. The callback
   *   URL is the current page's URL (`location.origin + location.pathname`), so
   *   that page must be on an origin you control and declared in that origin's
   *   `/.well-known/ii-auth-callbacks` allow-list. Use it for full-page sign-in
   *   that shouldn't need a user gesture to open a window (e.g. redirecting on a
   *   restricted route), or native apps handing off via universal links.
   *
   * With `'redirect'` the page unloads on each step and the flow re-runs on the
   * return load, so call `signIn` / `requestAttributes` directly on the page's
   * load (not deferred behind, say, a click handler): a fresh visit starts the
   * flow and the identity provider's return replays it to completion. Give each
   * flow its own route so its persisted state stays isolated.
   * @default 'window'
   * @see https://github.com/dfinity/wg-identity-authentication/blob/main/topics/icrc_167_browser_url_transport.md
   */
  transport?: 'window' | 'redirect';

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
   * Disables the default idle callback (sign-out & reload).
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
  // Set only in redirect mode, so the redirect-specific paths (nonce/key
  // journaling) can reach `memoize`. Undefined in the default 'window' mode.
  #urlTransport: UrlTransport | undefined;
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

    const transport =
      options.transport === 'redirect'
        ? new UrlTransport({
            url: identityProviderUrl.toString(),
            // The callback is this page: a fresh visit starts the flow and the
            // provider's return lands back here to replay it. Drop any query
            // and fragment so it stays stable across the redirect.
            callbackUrl: `${globalThis.location.origin}${globalThis.location.pathname}`,
          })
        : new PostMessageTransport({
            url: identityProviderUrl.toString(),
            windowOpenerFeatures: options.windowOpenerFeatures,
          });
    this.#urlTransport = transport instanceof UrlTransport ? transport : undefined;

    this.#signer = new Signer({
      transport,
      // Journal the derivation origin so it survives the top-level redirect: the
      // return load reconstructs this client from a query-less callback URL, so
      // `options.derivationOrigin` (like the identity provider) is no longer
      // available — the memoized value replays from the journal instead.
      // `memoize` returns synchronously for a synchronous producer, so the value
      // is usable directly here; in the window flow it is a passthrough that runs
      // the producer without persisting anything.
      derivationOrigin: this.memoize(() => options.derivationOrigin?.toString()),
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
    const maxTimeToLive = options?.maxTimeToLive ?? DEFAULT_MAX_TIME_TO_LIVE;
    const keyType = this.#options.keyType ?? ECDSA_KEY_LABEL;

    // Start session-key acquisition BEFORE opening the channel, awaiting it only
    // after. In the redirect flow the acquisition's first `transport.memoize`
    // runs synchronously when invoked, so its in-flight bump lands in the same
    // tick `signIn` is called — holding the transport's batch flush from the
    // very start of the flow rather than only after the `openChannel` await.
    // Under `Promise.all([signIn, requestAttributes])` this is what keeps a
    // faster concurrent request from flushing before this flow's delegation
    // request is buffered.
    const sessionKeyPromise: Promise<{
      key: SignIdentity | PartialIdentity;
      pendingKeySlot?: string;
    }> = this.#urlTransport
      ? this.#ensureSessionKeyForRedirectFlow(this.#urlTransport, keyType)
      : this.#ensureSessionKeyForWindowFlow(keyType).then((key) => ({ key }));
    // The acquisition is started eagerly, before the awaits below. If one of
    // those throws first, `sessionKeyPromise` is never awaited, so attach a
    // no-op rejection handler now to keep a later acquisition failure from
    // surfacing as an unhandled rejection. The `await` below still observes a
    // rejection and propagates it when reached.
    void sessionKeyPromise.catch(() => undefined);

    await this.#signer.openChannel();

    const { key, pendingKeySlot } = await sessionKeyPromise;

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

    // The flow is complete: the delegation is bound to this key and stored, so
    // the per-flow pending copy is no longer needed. Best-effort — the user is
    // already signed in, so a cleanup failure must not fail signIn(); a later
    // flow sweeps whatever is left behind.
    if (pendingKeySlot !== undefined) {
      try {
        await this.#storage.remove(pendingKeySlot);
        await unregisterPendingKey(this.#storage, pendingKeySlot);
      } catch {
        // ignore
      }
    }

    return this.#identity;
  }

  // Window flow: sign-in completes in a single load, so a fresh session key per
  // sign-in is enough (or the caller-provided identity), with nothing to
  // persist for a later load.
  async #ensureSessionKeyForWindowFlow(
    keyType: BaseKeyType,
  ): Promise<SignIdentity | PartialIdentity> {
    return this.#options.identity ?? (await generateKey(keyType));
  }

  // Redirect flow: `signIn` runs twice — once on the load that navigates to the
  // identity provider, and again on the return load that replays the delegation
  // minted for the FIRST load's key. Both runs must therefore use the same key.
  // A per-flow key id is journaled via the transport (stable across the
  // redirect) and the key is kept in storage under that id, so the return load
  // restores the same key rather than generating a fresh one that would not
  // match the replayed delegation. A caller-provided identity is already stable
  // across the redirect, so it is used as-is with nothing persisted.
  async #ensureSessionKeyForRedirectFlow(
    transport: UrlTransport,
    keyType: BaseKeyType,
  ): Promise<{ key: SignIdentity | PartialIdentity; pendingKeySlot?: string }> {
    if (this.#options.identity !== undefined) {
      return { key: this.#options.identity };
    }

    const keyId = await transport.memoize(() => globalThis.crypto.randomUUID());
    const pendingKeySlot = `${PENDING_KEY_PREFIX}${keyId}`;

    // Acquire the per-flow key inside a `memoize` producer so the transport
    // holds its batch flush across the (async) key restore/generate + storage
    // write. The transport coalesces concurrently issued requests into one
    // redirect by flushing on a macrotask once no memoize producer is in
    // flight; without this hold, a faster concurrent request (e.g. the nonce
    // path of `requestAttributes`) buffers first and trips that flush before
    // this flow's delegation request — issued only once the key is ready — is
    // buffered, splitting what should be one redirect into two.
    //
    // The key is captured in a closure, not read back after the producer: on
    // the FIRST load the producer sets `acquired`, so the delegation request
    // that follows is issued with no intervening storage read — a read there
    // would re-open the very flush gap this closes. The producer is skipped on
    // the replay load (its result is journaled), where the key is instead
    // restored from storage. Only the id is journaled; the key lives in storage.
    let acquired: SignIdentity | PartialIdentity | null = null;
    await transport.memoize(async () => {
      acquired = await restoreKeyAt(this.#storage, pendingKeySlot);
      if (acquired === null) {
        acquired = await generateKey(keyType);
        // Register before writing the key: if the write then fails, a stray
        // registry entry is harmless (swept on expiry), whereas a key with no
        // registry entry would leak un-sweepably.
        await sweepAndRegisterPendingKey(this.#storage, pendingKeySlot, Date.now());
        await this.#storage.set(pendingKeySlot, serializeKey(acquired));
      }
      return keyId;
    });

    const key = acquired ?? (await restoreKeyAt(this.#storage, pendingKeySlot));
    if (key === null) {
      throw new Error('Session key missing after acquisition');
    }
    return { key, pendingKeySlot };
  }

  /**
   * Requests signed identity attributes from the identity provider.
   *
   * The `nonce` is a callback that produces the 32-byte nonce (typically
   * fetched from the RP canister), returning a promise resolving to it. It is a
   * callback rather than a value so the redirect flow can journal the nonce and
   * reuse the exact same bytes when the flow replays on the return load,
   * instead of fetching a fresh single-use nonce that the signer never signed
   * against.
   *
   * In 'window' mode the callback lets the identity provider window open while the
   * nonce is still resolving, avoiding a perceived delay before the user sees
   * the prompt; auto-close of the signer transport channel is temporarily
   * disabled while awaiting so the window cannot be closed out from under the
   * pending flow.
   *
   * @param params - Request parameters.
   * @param params.keys - Attribute keys to request (e.g. `['email', 'name']`).
   * @param params.nonce - Produces the 32-byte nonce issued by the RP canister,
   *   as a promise resolving to it.
   * @returns Signed attribute data and signature.
   * @throws When the identity provider returns an error or an invalid response.
   */
  async requestAttributes(params: {
    keys: string[];
    nonce: () => Promise<Uint8Array>;
  }): Promise<SignedAttributes> {
    // In redirect mode the nonce is journaled (base64, since the journal is
    // JSON) so the replay on the return load signs against the same bytes.
    const nonceBytes = this.#urlTransport
      ? fromBase64(await this.#urlTransport.memoize(async () => toBase64(await params.nonce())))
      : await this.#resolveNonce(params.nonce);

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
   * Runs and journals a piece of your own async work so its result stays stable
   * across the `'redirect'` flow.
   *
   * In `'redirect'` mode the page unloads on each step and `signIn` /
   * `requestAttributes` re-run on the return load, so a value you compute on the
   * first visit (from `location`, a fetch, `crypto`, …) would otherwise be
   * recomputed — and may differ — on the return. Wrap it in `memoize`: it runs
   * `produce` once on the first visit, journals the result, and replays that
   * result on the return load instead of re-running. Use it for a value the
   * post-flow code depends on, e.g. the URL to navigate to once sign-in
   * completes:
   *
   * ```ts
   * const next = await authClient.memoize(
   *   () => new URLSearchParams(location.search).get('next') ?? '/',
   * );
   * await authClient.signIn();
   * location.assign(next); // the value captured before the redirect
   * ```
   *
   * Call `memoize` in a stable order relative to `signIn` / `requestAttributes`
   * across loads (same order every load — branch only on values recovered from
   * earlier results), and keep the result JSON-serializable, since the journal
   * is JSON.
   *
   * In `'window'` mode there is no redirect, so this simply runs `produce` and
   * returns its result without persisting anything.
   *
   * Mirrors the producer's shape: a synchronous `produce` returns its value
   * directly, an asynchronous one returns a promise. Awaiting the result is
   * always safe (`await` on a non-promise is a no-op); the synchronous form lets
   * a value be memoized where an `await` is not possible, such as in a
   * constructor.
   * @param produce - Produces the value to journal on the first load.
   * @returns The produced value, or the journaled value on a replay load.
   */
  memoize<T>(produce: () => Promise<T>): Promise<T>;
  memoize<T>(produce: () => T): T;
  memoize<T>(produce: () => T | Promise<T>): T | Promise<T> {
    if (this.#urlTransport) {
      return this.#urlTransport.memoize(produce);
    }
    return produce();
  }

  /**
   * Clears the stored session and resets the client to an anonymous state.
   *
   * @param options - Sign-out options.
   * @param options.returnTo - URL to navigate to after sign-out.
   */
  async signOut(options: { returnTo?: string } = {}): Promise<void> {
    await deleteStorage(this.#storage);

    this.#identity = new AnonymousIdentity();
    this.#chain = null;

    if (options.returnTo !== undefined) {
      // Navigate exactly as before (pushState, else location.href), but only to
      // a validated same-origin http(s) target, and feed that validated
      // `target.href` to both sinks rather than the raw `returnTo`. An invalid
      // or cross-origin `returnTo` is ignored, so the fallback can no longer be
      // turned into an open redirect or a `javascript:` execution.
      let target: URL | undefined;
      try {
        target = new URL(options.returnTo, window.location.href);
      } catch {
        target = undefined;
      }
      if (
        target !== undefined &&
        (target.protocol === 'https:' || target.protocol === 'http:') &&
        target.origin === window.location.origin
      ) {
        try {
          window.history.pushState({}, '', target.href);
        } catch {
          window.location.href = target.href;
        }
      }
    }
  }

  // Popup-mode nonce resolution. Start the fetch, then open the transport
  // channel so the identity provider window is visible while we wait, and
  // suspend auto-close so it can't fire mid-await (e.g. due to a close
  // scheduled by a prior request on the same signer). The original auto-close
  // setting is restored before sendRequest, so the next response resumes
  // normal close behaviour.
  async #resolveNonce(nonce: () => Promise<Uint8Array>): Promise<Uint8Array> {
    const value = nonce();
    await this.#signer.openChannel();
    const previousAutoClose = this.#signer.autoCloseTransportChannel;
    this.#signer.autoCloseTransportChannel = false;
    try {
      return await value;
    } finally {
      this.#signer.autoCloseTransportChannel = previousAutoClose;
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
      // Invoked without being awaited, so handle the promise here. Reload only
      // after teardown resolves, and only if it succeeded — a reload before or
      // without teardown lets #hydrate restore the still-valid session.
      this.idleManager?.registerCallback(() => {
        void this.signOut()
          .then(() => location.reload())
          .catch(() => {});
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

// Reads the pending-key registry, dropping malformed entries. The value comes
// from storage, so guard against corruption: keep only real pending-key slots
// with a finite expiry (a NaN expiry compares false forever and never sweeps;
// a foreign slot would make the sweep remove an unrelated storage key).
async function readPendingRegistry(storage: AuthClientStorage): Promise<PendingKeyEntry[]> {
  const raw = await storage.get(PENDING_KEYS_REGISTRY_KEY);
  if (typeof raw !== 'string') return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((entry): entry is PendingKeyEntry => {
      if (typeof entry !== 'object' || entry === null) return false;
      const { slot, expiresAt } = entry as PendingKeyEntry;
      return (
        typeof slot === 'string' &&
        slot.startsWith(PENDING_KEY_PREFIX) &&
        typeof expiresAt === 'number' &&
        Number.isFinite(expiresAt)
      );
    });
  } catch {
    return [];
  }
}

async function writePendingRegistry(
  storage: AuthClientStorage,
  entries: PendingKeyEntry[],
): Promise<void> {
  if (entries.length === 0) {
    await storage.remove(PENDING_KEYS_REGISTRY_KEY);
    return;
  }
  await storage.set(PENDING_KEYS_REGISTRY_KEY, JSON.stringify(entries));
}

// Removes expired pending-key slots, then registers `slot` with a fresh expiry.
async function sweepAndRegisterPendingKey(
  storage: AuthClientStorage,
  slot: string,
  now: number,
): Promise<void> {
  const entries = await readPendingRegistry(storage);
  const live: PendingKeyEntry[] = [];
  for (const entry of entries) {
    if (entry.slot === slot) continue; // re-registered with a fresh expiry below
    if (entry.expiresAt <= now) {
      await storage.remove(entry.slot);
    } else {
      live.push(entry);
    }
  }
  live.push({ slot, expiresAt: now + PENDING_KEY_TTL_MS });
  await writePendingRegistry(storage, live);
}

// Drops a slot from the pending-key registry once its flow completes.
async function unregisterPendingKey(storage: AuthClientStorage, slot: string): Promise<void> {
  const entries = await readPendingRegistry(storage);
  const remaining = entries.filter((entry) => entry.slot !== slot);
  if (remaining.length !== entries.length) {
    await writePendingRegistry(storage, remaining);
  }
}

/**
 * Loads a session key from a specific storage slot, deserializing by stored
 * shape (`CryptoKeyPair` → ECDSA, JSON string → Ed25519). Unlike
 * {@link restoreKey} it does not migrate from localStorage — it reads only the
 * given slot, as used for a redirect flow's per-flow pending key.
 * @param storage - The storage backend.
 * @param storageKey - The slot to read.
 */
async function restoreKeyAt(
  storage: AuthClientStorage,
  storageKey: string,
): Promise<SignIdentity | PartialIdentity | null> {
  const stored = await storage.get(storageKey);
  if (!stored) return null;

  try {
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
