import { AnonymousIdentity, type Identity, type SignIdentity } from '@icp-sdk/core/agent';
import {
  type DelegationChain,
  DelegationIdentity,
  isDelegationValid,
  PartialDelegationIdentity,
  type PartialIdentity,
} from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { Signer } from '@icp-sdk/signer';
import { PostMessageTransport, UrlTransport } from '@icp-sdk/signer/web';
import {
  type Credential,
  type CredentialStorage,
  PENDING_SLOT,
  SESSION_SLOT,
} from './credential-storage.js';
import { IdbCredentialStorage } from './idb-credential-storage.js';
import { IdleManager, type IdleManagerOptions } from './idle-manager.js';
import { LocalStateStorage, type StateStorage } from './state-storage.js';

const NANOSECONDS_PER_SECOND = BigInt(1_000_000_000);
const SECONDS_PER_HOUR = BigInt(3_600);
const NANOSECONDS_PER_HOUR = NANOSECONDS_PER_SECOND * SECONDS_PER_HOUR;

const IDENTITY_PROVIDER_DEFAULT = 'https://id.ai/authorize';
const DEFAULT_MAX_TIME_TO_LIVE = BigInt(8) * NANOSECONDS_PER_HOUR;

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
  credentialStorage?: CredentialStorage;

  /**
   * Where the state of the sign-in is kept: which account is signed in here,
   * and until when. Defaults to `localStorage`.
   *
   * This is what {@link AuthClient.isAuthenticated} answers from, which is why
   * it is a store of its own rather than something read back out of
   * {@link AuthClientCreateOptions.credentialStorage}: the state has to be
   * readable without awaiting, and a credential store does not have to be.
   */
  stateStorage?: StateStorage;

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
/**
 * What the state adds up to for this origin, once the clock is applied.
 *
 * The record says what is signed in and whether this origin holds a credential
 * for it; this says what that means. The principal is present in every case
 * where a record exists, which is what a silent re-issue needs in order to name
 * the account it is for.
 */
export type SessionStatus =
  | { status: 'signed-in'; principal: Principal }
  /**
   * A sign-in this origin has no credential for, so it cannot act on it yet.
   *
   * Only reachable where the record reaches past this origin: a sibling
   * subdomain signed in and this one has not acquired its own credential. The
   * silent re-issue that fixes it can still fail, and the fallback is asking the
   * user.
   */
  | { status: 'signed-in-elsewhere'; principal: Principal }
  | { status: 'expired'; principal: Principal }
  | { status: 'signed-out' };

export class AuthClient {
  #identity: Identity | PartialIdentity = new AnonymousIdentity();
  #chain: DelegationChain | null = null;
  #credentialStorage: CredentialStorage;
  #stateStorage: StateStorage;
  #signer: Signer;
  // Set only in redirect mode, so the redirect-specific paths (nonce/key
  // journaling) can reach `memoize`. Undefined in the default 'window' mode.
  #urlTransport: UrlTransport | undefined;
  #options: AuthClientCreateOptions;
  #initPromise: Promise<void> | null = null;
  idleManager: IdleManager | undefined;

  constructor(options: AuthClientCreateOptions = {}) {
    this.#options = options;
    this.#credentialStorage = options.credentialStorage ?? new IdbCredentialStorage();
    this.#stateStorage = options.stateStorage ?? new LocalStateStorage();

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
    return this.getStatus().status === 'signed-in';
  }

  /**
   * Who this origin can act as, or `undefined` where it cannot act.
   *
   * The same question {@link isAuthenticated} answers, returning who rather than
   * whether — so the two never disagree. Synchronous, and read from the state
   * rather than from whatever material happens to be held, so a page renders on
   * it without opening a store and without waiting for a mint. That is the
   * difference from `(await getIdentity()).getPrincipal()`, which is asynchronous
   * and, on a load with no delegation worth adopting, waits for one to be minted.
   *
   * A principal here means calls made as it will be accepted, so an expired
   * record answers `undefined` even though it still names an account, and so does
   * a record naming an account this origin holds nothing for. Returning one
   * anyway would have an application acting on a session that has ended: the
   * check most reach for is `if (getPrincipal())`, and it has to mean what it
   * looks like it means.
   *
   * {@link getStatus} is where those cases are readable, and it carries the
   * account principal in each of them — so nothing is lost by this being narrow,
   * and an application wanting to say whose session ended asks there.
   */
  getPrincipal(): Principal | undefined {
    const status = this.getStatus();
    return status.status === 'signed-in' ? status.principal : undefined;
  }

  /**
   * What this origin's sign-in amounts to right now.
   *
   * Four cases, tested in one place so an application does not have to know the
   * order in which they exclude each other. Reading the record directly means
   * recombining `held` and the expiry at every call site, which is where the
   * difference between "signed in here" and "signed in on this domain" gets lost.
   *
   * Reads the state rather than the delegation, so the answer needs no
   * asynchronous store and a page load can render on it.
   */
  getStatus(): SessionStatus {
    const state = this.#stateStorage.get();
    if (state === null) return { status: 'signed-out' };

    const { principal } = state;
    // Expiry first: a record that has run out says nothing about who may act,
    // whoever it belongs to, and an application showing "your session ended"
    // wants that ahead of the rest.
    if (BigInt(Date.now()) * BigInt(1_000_000) >= state.expiration) {
      return { status: 'expired', principal };
    }
    // `held` is what separates "this origin can act" from "someone is signed in
    // within this store's reach" — the second is a sibling subdomain that has not
    // acquired a credential of its own.
    return state.held
      ? { status: 'signed-in', principal }
      : { status: 'signed-in-elsewhere', principal };
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
      pending?: boolean;
    }> = this.#urlTransport
      ? this.#ensureSessionKeyForRedirectFlow(this.#urlTransport)
      : this.#ensureSessionKeyForWindowFlow().then((key) => ({ key }));
    // The acquisition is started eagerly, before the awaits below. If one of
    // those throws first, `sessionKeyPromise` is never awaited, so attach a
    // no-op rejection handler now to keep a later acquisition failure from
    // surfacing as an unhandled rejection. The `await` below still observes a
    // rejection and propagates it when reached.
    void sessionKeyPromise.catch(() => undefined);

    // openChannel() must stay the first await: it can open a popup window,
    // which the browser may block unless it happens in the same tick as the
    // click that called signIn().
    await this.#signer.openChannel();

    // Wait for the constructor's session restore, so this flow's storage
    // writes cannot interleave with hydration's reads.
    await this.#init();

    const { key, pending } = await sessionKeyPromise;

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

    // Promote: the key and the delegation issued to it become one record under
    // the session slot, and the ceremony's own copy goes.
    await this.#persistSession(key, this.#chain);

    // Best-effort — the user is already signed in, so a cleanup failure must not
    // fail signIn(), and the next ceremony overwrites what is left behind.
    if (pending) {
      try {
        await this.#credentialStorage.remove(PENDING_SLOT);
      } catch {
        // ignore
      }
    }

    return this.#identity;
  }

  // Window flow: sign-in completes in a single load, so a fresh session key per
  // sign-in is enough (or the caller-provided identity), with nothing to
  // persist for a later load.
  async #ensureSessionKeyForWindowFlow(): Promise<SignIdentity | PartialIdentity> {
    return this.#options.identity ?? (await this.#credentialStorage.create());
  }

  // Redirect flow: `signIn` runs twice — once on the load that navigates to the
  // identity provider, and again on the return load that replays the delegation
  // minted for the FIRST load's key. Both runs must therefore use the same key,
  // so the first load writes it to the pending slot and the return load reads it
  // back. A caller-provided identity is already stable across the redirect, so it
  // is used as-is with nothing persisted.
  async #ensureSessionKeyForRedirectFlow(
    transport: UrlTransport,
  ): Promise<{ key: SignIdentity | PartialIdentity; pending?: boolean }> {
    if (this.#options.identity !== undefined) {
      return { key: this.#options.identity };
    }

    // Acquire the key inside a `memoize` producer so the transport holds its
    // batch flush across the (async) key read/create + storage write. The
    // transport coalesces concurrently issued requests into one redirect by
    // flushing on a macrotask once no memoize producer is in flight; without
    // this hold, a faster concurrent request (e.g. the nonce path of
    // `requestAttributes`) buffers first and trips that flush before this flow's
    // delegation request — issued only once the key is ready — is buffered,
    // splitting what should be one redirect into two.
    //
    // The key is captured in a closure, not read back after the producer: on the
    // FIRST load the producer sets `acquired`, so the delegation request that
    // follows is issued with no intervening storage read — a read there would
    // re-open the very flush gap this closes. The producer is skipped on the
    // replay load (its result is journaled), where the key is instead read from
    // the pending slot.
    //
    // What is journaled is the key's *public* half: not a secret, it survives the
    // redirect as text, and on the return load it says whether the pending slot
    // still holds the key this ceremony started with.
    let acquired: SignIdentity | null = null;
    const startedWith = await transport.memoize(async () => {
      const stored = await this.#credentialStorage.get(PENDING_SLOT);
      if (stored !== null) {
        acquired = stored.identity;
      } else {
        acquired = await this.#credentialStorage.create();
        await this.#credentialStorage.set(PENDING_SLOT, { identity: acquired });
      }
      return publicKeyOf(acquired);
    });

    const key: SignIdentity | PartialIdentity | null =
      acquired ?? (await this.#credentialStorage.get(PENDING_SLOT))?.identity ?? null;
    if (key === null) {
      throw new Error('Session key missing after acquisition');
    }
    if (publicKeyOf(key) !== startedWith) {
      // Another sign-in in this browser took the pending slot while this one was
      // away. Its delegation was minted for a different key, so this flow cannot
      // finish; the caller retries, and by then the session that superseded it
      // has usually been promoted.
      throw new Error('This sign-in was superseded by another one in this browser');
    }
    return { key, pending: true };
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
    // Wait for the constructor's session restore: hydration racing the
    // deletion below could re-populate the identity from already-read state.
    await this.#init();
    await this.#endSession();

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
    const restored = await this.#restoreSession();
    const key = this.#options.identity ?? restored?.identity;
    const chain = restored?.chain;
    if (!key || !chain) {
      // Nothing to restore, so this origin cannot act — and saying otherwise is
      // what the state leading forbids. Discarded rather than removed, because a
      // record that reaches past this origin belongs to whoever published it.
      if (this.#stateStorage.get()?.held) await this.#dropSession();
      return;
    }

    // The state decides whether this origin is signed in, so a chain it does not
    // back belongs to a sign-in that has ended: drop it rather than restore it,
    // or getIdentity() would hand back an identity isAuthenticated() calls
    // signed out. Asked after the chain is read, so a visitor who was never
    // signed in removes nothing.
    if (this.#stateStorage.get() === null) {
      await this.#endSession();
      return;
    }

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

  /**
   * Stores the session as one record and records the state it puts this origin
   * in, so {@link isAuthenticated} can answer without reading it back.
   */
  async #persistSession(
    identity: SignIdentity | PartialIdentity,
    chain: DelegationChain,
  ): Promise<void> {
    // A PartialIdentity is the caller's own and cannot sign, so there is nothing
    // worth storing: the client uses it for this run and restores nothing later.
    if (!('toDer' in identity)) {
      await this.#credentialStorage.set(SESSION_SLOT, { identity, chain });
    }

    let earliest: bigint | null = null;
    for (const { delegation } of chain.delegations) {
      if (earliest === null || delegation.expiration < earliest) {
        earliest = delegation.expiration;
      }
    }
    if (earliest !== null) {
      // Both fields come off the chain: it is rooted at the account's key, and
      // the sign-in lasts as long as its earliest delegation.
      this.#stateStorage.set({
        principal: Principal.selfAuthenticating(new Uint8Array(chain.publicKey)),
        expiration: earliest,
      });
    }
  }

  /**
   * Loads the stored session. Returns `null` and ends the sign-in where the
   * delegation has expired or the record cannot be read.
   */
  async #restoreSession(): Promise<Credential | null> {
    const credential = await this.#credentialStorage.get(SESSION_SLOT);
    if (credential === null) return null;

    // A record with no chain is not a session: only a ceremony's own slot may
    // hold a key alone.
    if (credential.chain === undefined || !isDelegationValid(credential.chain)) {
      await this.#endSession();
      return null;
    }
    return credential;
  }

  /**
   * Ends the sign-in: what a user pressing sign out asks for.
   *
   * Retracts the state, including anything the store publishes beyond this
   * origin, because a sibling reading a shared record must stop seeing one.
   */
  async #endSession(): Promise<void> {
    this.#stateStorage.remove();
    await this.#clearCredentials();
  }

  /**
   * Drops this origin's claim on a sign-in without retracting what is published.
   *
   * What finding out does, which is a different act. An origin whose chain turns
   * out to be dead cannot tell a revoked session from one a sibling replaced by
   * signing in — and in the second case the shared record was written by that
   * sibling a moment ago, so retracting it would tell it that the session it just
   * obtained is gone.
   */
  async #dropSession(): Promise<void> {
    this.#stateStorage.discard?.();
    await this.#clearCredentials();
  }

  // Always every slot, so no caller can end a sign-in halfway by naming one. The
  // state is retracted before this by both callers: it is what says whether this
  // origin is signed in, and a teardown that failed partway must not leave it
  // saying yes.
  async #clearCredentials(): Promise<void> {
    await this.#credentialStorage.remove(SESSION_SLOT);
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

/** A key's public half as text, for comparing two keys without holding both. */
function publicKeyOf(key: SignIdentity | PartialIdentity): string {
  return toBase64(new Uint8Array(key.getPublicKey().toDer()));
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
