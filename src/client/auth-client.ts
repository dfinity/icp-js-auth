import {
  AnonymousIdentity,
  type HttpAgentOptions,
  type Identity,
  type SignIdentity,
} from '@icp-sdk/core/agent';
import {
  type DelegationChain,
  ECDSAKeyIdentity,
  isDelegationValid,
  type PartialIdentity,
} from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { Signer } from '@icp-sdk/signer';
import { PostMessageTransport, UrlTransport } from '@icp-sdk/signer/web';
import type { AppCredential } from './app-delegation-source.js';
import { fromBase64, toBase64 } from './base64.js';
import { IdbIdentityStorage } from './idb-identity-storage.js';
import type { IdentityStorage } from './identity-storage.js';
import { IdleManager, type IdleManagerOptions } from './idle-manager.js';
import { LocalSessionStorage } from './local-session-storage.js';
import { requestSessionDelegation } from './session-delegation.js';
import { SessionIdentity } from './session-identity.js';
import { SessionMinter } from './session-minter.js';
import type { Session, SessionStorage } from './session-storage.js';

const IDENTITY_PROVIDER_DEFAULT = 'https://id.ai/authorize';
const IDENTITY_CANISTER_DEFAULT = 'rdmx6-jaaaa-aaaaa-aaadq-cai';

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
  identity?: SignIdentity;

  /**
   * Where the session signing identity (key pair) is persisted. The
   * implementation owns the key algorithm — switch it to switch algorithms
   * (e.g. ECDSA → Ed25519).
   * @default IdbIdentityStorage
   */
  identityStorage?: IdentityStorage;

  /**
   * Where the session is persisted. A session carries no private material, so it
   * can live in a synchronous, observable store; the default notifies other tabs
   * of a sign-in or sign-out via the `storage` event.
   * @default LocalSessionStorage
   */
  sessionStorage?: SessionStorage;

  /**
   * Idle timeout configuration.
   * @default after 10 minutes, invalidates the identity
   */
  idleOptions?: IdleOptions;

  /**
   * Where Internet Identity is: the URL a sign-in ceremony renders at, and the
   * canister that mints and revokes this application's delegations.
   *
   * Both halves are needed because they are not the same address. A custom domain
   * can front the mainnet canister, and a local deployment changes both.
   *
   * @default { authorizeUrl: "https://id.ai/authorize", canisterId: "rdmx6-jaaaa-aaaaa-aaadq-cai" }
   */
  identityProvider?: {
    /** The authorize URL a ceremony is rendered at. */
    authorizeUrl?: string | URL;

    /** The canister that mints and revokes this application's delegations. */
    canisterId?: Principal | string;
  };

  /**
   * Options for the agent that calls that canister.
   *
   * Omit it and the agent applies its own defaults, which reach mainnet. A local
   * replica needs `{ host, shouldFetchRootKey: true }`. `identity` is not among
   * them: the agent signs as the session, which is what a mint call rests on.
   */
  agentOptions?: Omit<HttpAgentOptions, 'identity'>;

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
   * The longest this session may last, in nanoseconds.
   *
   * A ceiling rather than a request: what the user chooses at consent wins over
   * it, an organization's policy may narrow it further, and Internet Identity
   * clamps the result to between ten minutes and thirty days. Omit it to accept
   * whatever the user is offered.
   *
   * The app delegations minted from the session are five minutes regardless, and
   * are not requestable.
   */
  maxTimeToLive?: bigint;

  /**
   * URL to navigate to once sign-in completes, ignored unless it is a
   * same-origin http(s) target. In the `'redirect'` flow it is journaled so it
   * survives the round-trip, and the navigation replaces the current history
   * entry so a transient sign-in page is not left behind.
   */
  returnTo?: string;
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
  /** The session the identity on show was built for, if it was built from one. */
  #presenting: Session | undefined;
  #identityStorage: IdentityStorage;
  readonly #identityCanisterId: Principal;
  #sessionStorage: SessionStorage;
  #signer: Signer;
  // Set only in redirect mode, so the redirect-specific paths (nonce/key
  // journaling) can reach `memoize`. Undefined in the default 'window' mode.
  #urlTransport: UrlTransport | undefined;
  #options: AuthClientCreateOptions;
  // Makes the key each mint gets a delegation for. Non-extractable, because it
  // crosses to other tabs of this origin as a handle that signs and cannot be
  // copied, and made afresh each time, because a key and its delegation expire
  // together and one outliving the other carries nothing.
  readonly #newAppKey = (): Promise<SignIdentity> =>
    ECDSAKeyIdentity.generate({ extractable: false });
  #initPromise: Promise<void> | null = null;
  // Listeners registered via subscribe(), and the live subscription to the
  // delegation storage that drives them. The storage subscription is opened
  // lazily on the first subscribe() and closed when the last one leaves.
  #changeListeners = new Set<() => void>();
  #unsubscribeSession: (() => void) | undefined;
  idleManager: IdleManager | undefined;

  constructor(options: AuthClientCreateOptions = {}) {
    this.#options = options;
    this.#identityStorage = options.identityStorage ?? new IdbIdentityStorage();
    this.#sessionStorage = options.sessionStorage ?? new LocalSessionStorage();
    this.#identityCanisterId = Principal.from(
      options.identityProvider?.canisterId ?? IDENTITY_CANISTER_DEFAULT,
    );

    const identityProviderUrl = new URL(
      options.identityProvider?.authorizeUrl?.toString() || IDENTITY_PROVIDER_DEFAULT,
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
   *
   * Synchronous: the delegation lives in synchronous storage, so its earliest
   * expiry is read and checked without touching IndexedDB.
   */
  isAuthenticated(): boolean {
    const session = this.#sessionStorage.get();
    return session !== null && isDelegationValid(session.chain);
  }

  /**
   * Registers a listener fired when the session changes outside this client —
   * a sign-in or sign-out in another tab, or anywhere else the configured store
   * shares the session from. The client re-derives its identity before the
   * listener runs, so {@link getIdentity} / {@link isAuthenticated} already
   * reflect the change inside the callback.
   *
   * @param listener - Invoked on each external session change.
   * @returns A function that unregisters the listener.
   */
  subscribe(listener: () => void): () => void {
    this.#changeListeners.add(listener);
    if (this.#unsubscribeSession === undefined) {
      this.#unsubscribeSession = this.#sessionStorage.subscribe(() => {
        // #reconcile() is async and may reject (e.g. identityStorage.get()
        // failing to open IndexedDB). Swallow it: a failed re-derive leaves the
        // current state in place, which is preferable to an unhandled rejection.
        this.#reconcile().catch(() => {});
      });
    }
    return () => {
      this.#changeListeners.delete(listener);
      if (this.#changeListeners.size === 0) {
        this.#unsubscribeSession?.();
        this.#unsubscribeSession = undefined;
      }
    };
  }

  /**
   * Releases resources held by the client: the session-storage subscription
   * and any registered {@link subscribe} listeners. Call it when discarding a
   * client so its storage listener does not outlive it.
   */
  dispose(): void {
    if (this.#identity instanceof SessionIdentity) this.#identity.dispose();
    this.#unsubscribeSession?.();
    this.#unsubscribeSession = undefined;
    this.#changeListeners.clear();
  }

  /**
   * Opens the identity provider, requests a delegation, and returns the authenticated identity.
   *
   * @param options - Sign-in options.
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
    // Journal returnTo up front so it survives a 'redirect' round-trip, and only
    // when provided so the flow's journal is unchanged for callers that omit it.
    // Validate to a same-origin URL *inside* the producer, so only a safe href
    // (or null) is ever journaled — never the raw, possibly cross-origin, value.
    const rawReturnTo = options?.returnTo;
    const returnTo =
      rawReturnTo === undefined
        ? undefined
        : this.memoize(() => sameOriginTarget(rawReturnTo)?.href ?? null);

    // Start session-identity acquisition BEFORE opening the channel, awaiting it
    // only after. In the redirect flow the acquisition's first `transport.memoize`
    // runs synchronously when invoked, so its in-flight bump lands in the same
    // tick `signIn` is called — holding the transport's batch flush from the
    // very start of the flow rather than only after the `openChannel` await.
    // Under `Promise.all([signIn, requestAttributes])` this is what keeps a
    // faster concurrent request from flushing before this flow's delegation
    // request is buffered.
    const identityPromise: Promise<SignIdentity | PartialIdentity> = this.#urlTransport
      ? this.#acquireIdentityForRedirectFlow(this.#urlTransport)
      : this.#acquireIdentityForWindowFlow();
    // The acquisition is started eagerly, before the awaits below. If one of
    // those throws first, `identityPromise` is never awaited, so attach a no-op
    // rejection handler now to keep a later acquisition failure from surfacing
    // as an unhandled rejection. The `await` below still observes a rejection
    // and propagates it when reached.
    void identityPromise.catch(() => undefined);

    // openChannel() must stay the first await: it can open a popup window,
    // which the browser may block unless it happens in the same tick as the
    // click that called signIn().
    await this.#signer.openChannel();

    // Wait for the constructor's session restore, so this flow's storage
    // writes cannot interleave with hydration's reads.
    await this.#init();

    const key = await identityPromise;

    if (!('sign' in key)) {
      // Unreachable for a typed caller, since `identity` is a SignIdentity.
      // Minting is a canister call signed by the session key, so a key that
      // cannot sign cannot hold a session, and failing here beats handing back
      // an identity whose first request fails for a reason nothing explains.
      throw new Error('A session needs a key that can sign');
    }

    const sessionChain = await requestSessionDelegation(this.#signer, {
      sessionPublicKey: key.getPublicKey().toDer(),
      maxTimeToLive: options?.maxTimeToLive,
      derivationOrigin: this.#options.derivationOrigin?.toString(),
    });

    // Mint inside the ceremony the user is already waiting through, so the first
    // request after signing in does not wait. This is also where the account key
    // comes from: the chain above is rooted at the session's own key, and only a
    // mint reports the key an application's canisters will see.
    const minter = await this.#minterFor(key, sessionChain);
    const appKey = await this.#newAppKey();
    const appDelegation = await minter.mint(appKey.getPublicKey().toDer());
    const session: Session = { chain: sessionChain, accountKey: appDelegation.publicKey };

    this.#setIdentity(
      this.#sessionIdentity(minter, session, {
        key: appKey,
        chain: appDelegation,
      }),
      session,
    );

    const idleOptions = this.#options?.idleOptions;
    if (!this.idleManager && !idleOptions?.disableIdle) {
      this.idleManager = IdleManager.create(idleOptions);
      this.#registerDefaultIdleCallback();
    }

    // Persist the session now that authentication has succeeded. In the window
    // flow the identity was only minted (not stored) during acquisition, so it
    // is written here — a cancelled or failed ceremony therefore never
    // overwrites an existing valid session's key. The redirect flow already
    // persisted it on the outbound load (it had to survive the navigation), and
    // a caller-provided identity is used as-is and never persisted.
    if (this.#urlTransport === undefined && this.#options.identity === undefined) {
      // `options.identity` is undefined, so `key` came from
      // `identityStorage.create()`, which returns a full SignIdentity.
      await this.#identityStorage.set(key as SignIdentity);
    }
    this.#sessionStorage.set(session);

    if (typeof returnTo === 'string') {
      // Leave the (possibly transient) sign-in page for the already-validated
      // return target, replacing it so it and the redirect chain aren't kept in
      // history.
      location.replace(returnTo);
    }

    return this.#identity;
  }

  // Window flow: sign-in completes in a single load. Mint a fresh session
  // identity (or use the caller-provided one) but do NOT persist it yet —
  // signIn writes it only once the delegation is obtained.
  async #acquireIdentityForWindowFlow(): Promise<SignIdentity | PartialIdentity> {
    return this.#options.identity ?? (await this.#identityStorage.create());
  }

  // Redirect flow: `signIn` runs twice — once on the load that navigates to the
  // identity provider, and again on the return load that replays the delegation
  // minted for the FIRST load's key. Both runs must therefore use the same
  // identity. Minting + persisting is gated behind `transport.memoize` so it
  // runs once, on the first load; the return load skips it (the memoized result
  // replays) and restores the same identity from storage. Unlike the window
  // flow the identity must be persisted here, before success — the page unloads
  // before the delegation returns, so the return load has nothing else to
  // restore from. A caller-provided identity is already stable across the
  // redirect, so it is used as-is with nothing persisted.
  async #acquireIdentityForRedirectFlow(
    transport: UrlTransport,
  ): Promise<SignIdentity | PartialIdentity> {
    if (this.#options.identity !== undefined) {
      return this.#options.identity;
    }

    // Mint + persist inside a `memoize` producer so the transport holds its
    // batch flush across the (async) identity generation + storage write. The
    // transport coalesces concurrently issued requests into one redirect by
    // flushing on a macrotask once no memoize producer is in flight; without
    // this hold, a faster concurrent request (e.g. the nonce path of
    // `requestAttributes`) buffers first and trips that flush before this flow's
    // delegation request — issued only once the key is ready — is buffered,
    // splitting what should be one redirect into two.
    //
    // The identity is captured in a closure, not read back after the producer:
    // on the FIRST load the producer sets `created`, so the delegation request
    // that follows is issued with no intervening storage read — a read there
    // would re-open the very flush gap this closes. The producer is skipped on
    // the replay load (its result is journaled), where the identity is instead
    // restored from storage.
    let created: SignIdentity | null = null;
    await transport.memoize(async () => {
      created = await this.#identityStorage.create();
      await this.#identityStorage.set(created);
      return true;
    });

    const identity = created ?? (await this.#identityStorage.get());
    if (identity === null) {
      throw new Error('Session identity missing after acquisition');
    }
    return identity;
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

    // End the session at the canister first, so access stops within one app
    // delegation's lifetime instead of running to the session's own expiry.
    // Clearing local state only stops this browser using what it holds.
    await this.#revokeSession();

    this.#sessionStorage.remove();
    await this.#identityStorage.remove();

    this.#identity = new AnonymousIdentity();

    if (options.returnTo !== undefined) {
      // Navigate only to a validated same-origin http(s) target, so an invalid
      // or cross-origin `returnTo` can't be turned into an open redirect or a
      // `javascript:` execution.
      const target = sameOriginTarget(options.returnTo);
      if (target !== undefined) {
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

  // Attempts to restore a previous session (signing identity + delegation
  // chain) from storage. If found and still valid, sets #identity so the client is ready to use without a new signIn().
  async #hydrate(): Promise<void> {
    const key = this.#options.identity ?? (await this.#identityStorage.get());
    if (key === null) return;

    const session = this.#sessionStorage.get();
    if (session === null) return;
    if (!isDelegationValid(session.chain) || !keyMatchesChain(key, session.chain)) {
      // Drop the delegation so isAuthenticated() and later reads agree. Either
      // it expired, or the stored key and delegation are from different
      // sign-ins (e.g. an abandoned redirect re-auth wrote a new key beside the
      // old delegation) — assembling those would sign with a key the delegation
      // doesn't authorize. A fresh signIn() overwrites the identity, so leave
      // it in place.
      //
      // Discarded rather than removed: what is wrong is this origin's copy, and
      // a store that shares the session further keeps announcing it, because a
      // sibling holding a good copy has learned nothing here.
      this.#sessionStorage.discard();
      return;
    }
    // No mint here: the account key was stored with the session, so who is
    // signed in is known without one, and the first request mints.
    this.#setIdentity(
      this.#sessionIdentity(await this.#minterFor(key, session.chain), session),
      session,
    );

    if (!this.#options.idleOptions?.disableIdle && !this.idleManager) {
      this.idleManager = IdleManager.create(this.#options.idleOptions);
      this.#registerDefaultIdleCallback();
    }
  }

  // Re-reads the delegation after an external change and re-derives the
  // identity, then notifies
  // subscribers. A removed or expired delegation resets to anonymous; a new one
  // is paired with the persisted signing identity.
  async #reconcile(): Promise<void> {
    const session = this.#sessionStorage.get();
    // A write on this tab notifies this tab, so signing in lands here straight
    // after it has already built the identity for that session — and rebuilding
    // it would throw away the credential the ceremony just minted, since nothing
    // answers the ask for one in a single tab. Reconcile is for a change made
    // elsewhere; the session it already presents is not one.
    if (
      session !== null &&
      this.#presenting !== undefined &&
      isSameSession(session, this.#presenting) &&
      this.#identity instanceof SessionIdentity
    ) {
      return;
    }
    if (session === null || !isDelegationValid(session.chain)) {
      this.#identity = new AnonymousIdentity();
      this.#notify();
      return;
    }

    const key = this.#options.identity ?? (await this.#identityStorage.get());
    if (key === null) {
      // The delegation is present but its signing identity is not yet visible in
      // this context. Leave the current state untouched rather than asserting a
      // session we cannot sign for.
      return;
    }
    if (!keyMatchesChain(key, session.chain)) {
      // Key and session are from different sign-ins; they can't be assembled
      // into a usable identity. Unlike #hydrate this doesn't mutate storage —
      // reconcile only reflects external state.
      this.#identity = new AnonymousIdentity();
      this.#notify();
      return;
    }

    this.#setIdentity(
      this.#sessionIdentity(await this.#minterFor(key, session.chain), session),
      session,
    );
    this.#notify();
  }

  #notify(): void {
    for (const listener of this.#changeListeners) {
      listener();
    }
  }

  // Derives #identity from a signing key and delegation chain. A PartialIdentity
  // (public key only, no signing capability) yields a PartialDelegationIdentity.
  /**
   * Asks the canister to delete the session, and gives up quietly if it cannot.
   *
   * A failure here must not stop a sign-out: a user who pressed it has to end up
   * signed out on the device in front of them, and the session expires on its own
   * either way. Revocation is what makes a sign-out reach the delegations already
   * issued, so it is attempted first and its outcome does not change the rest.
   */
  async #revokeSession(): Promise<void> {
    const session = this.#sessionStorage.get();
    const key = this.#options.identity ?? (await this.#identityStorage.get());
    if (session === null || key === null) return;

    try {
      const minter = await this.#minterFor(key, session.chain);
      await minter.revoke();
    } catch {
      // Offline, or a session the canister no longer has. Either way there is
      // nothing left to do here and nothing worth telling the caller.
    }
  }

  /** An agent pointed at Internet Identity, signing as the session. */
  #minterFor(sessionKey: SignIdentity, sessionChain: DelegationChain): Promise<SessionMinter> {
    return SessionMinter.create({
      sessionKey,
      sessionChain,
      canisterId: this.#identityCanisterId,
      agentOptions: this.#options.agentOptions,
    });
  }

  /**
   * Replaces the current identity, releasing the one it displaces.
   *
   * A `SessionIdentity` holds a credential, at most one mint in flight and an
   * armed refresh. Dropping the reference without disposing leaves that timer to
   * fire and record the session as used on behalf of an object nothing can reach.
   */
  #setIdentity(next: Identity, session?: Session): void {
    if (this.#identity instanceof SessionIdentity && this.#identity !== next) {
      this.#identity.dispose();
    }
    this.#identity = next;
    this.#presenting = session;
  }

  #sessionIdentity(
    source: SessionMinter,
    session: Session,
    initial?: AppCredential,
  ): SessionIdentity {
    return new SessionIdentity({
      newKey: this.#newAppKey,
      accountKey: session.accountKey,
      sessionExpiresAtMs: earliestExpiryMs(session.chain),
      source,
      initial,
      onSessionGone: () => {
        // Storage is shared by every tab of this origin, so what is stored is not
        // necessarily the session that just died. Signing in again replaces a
        // browser's session, so a tab still holding the old one is refused while
        // the tab that signed in is working fine — and clearing here would take
        // its session with it.
        const stored = this.#sessionStorage.get();
        if (stored !== null && !isSameSession(stored, session)) {
          // A newer session is stored, and it belongs to the same person in the
          // same browser. Adopt it rather than destroying it.
          void this.#reconcile();
          return;
        }

        // Discarded rather than removed. This client found out the session is
        // gone; it was not asked to end one, and a sibling that signed in a
        // moment ago has written a hint that is perfectly good.
        this.#sessionStorage.discard();
        // The session key signs for this session and nothing else, so it has no
        // use once the session is gone, and leaving it would keep a key with no
        // chain to go with it.
        void this.#identityStorage.remove();
        this.#identity = new AnonymousIdentity();
        this.#notify();
      },
    });
  }

  #registerDefaultIdleCallback() {
    const idleOptions = this.#options?.idleOptions;
    if (!idleOptions?.onIdle && !idleOptions?.disableDefaultIdleCallback) {
      // Invoked without being awaited, so handle the promise here. `signOut`
      // clears storage, which notifies subscribers, so a client with a
      // `subscribe` listener re-renders signed-out in place. Only reload when
      // nothing is listening (the legacy behavior for apps that don't observe
      // changes), and only after teardown resolves — a reload before or without
      // teardown lets #hydrate restore the still-valid session.
      this.idleManager?.registerCallback(() => {
        void this.signOut()
          .then(() => {
            if (this.#changeListeners.size === 0) location.reload();
          })
          .catch(() => {});
      });
    }
  }
}

/**
 * Resolves a `returnTo` string against the current location and returns it only
 * when it is a same-origin http(s) URL; otherwise `undefined`. Keeps a
 * cross-origin, protocol-relative, or `javascript:` value from being navigated to.
 * @param returnTo - The caller-supplied return target.
 */
function sameOriginTarget(returnTo: string): URL | undefined {
  let target: URL;
  try {
    target = new URL(returnTo, window.location.href);
  } catch {
    return undefined;
  }
  if (
    (target.protocol === 'https:' || target.protocol === 'http:') &&
    target.origin === window.location.origin
  ) {
    return target;
  }
  return undefined;
}

/**
 * Whether `key` is the session key the delegation chain terminates in — the
 * chain's innermost delegation must target this key's public key. A mismatch
 * means the stored key and delegation came from different sign-ins, so pairing
 * them would produce an identity that signs with a key the delegation does not
 * authorize; the caller must discard the session instead.
 * @param key - The signing (or partial) identity restored from storage.
 * @param chain - The delegation chain restored from storage.
 */
function keyMatchesChain(key: SignIdentity | PartialIdentity, chain: DelegationChain): boolean {
  const leaf = chain.delegations[chain.delegations.length - 1]?.delegation.pubkey;
  if (leaf === undefined) return false;
  return bytesEqual(new Uint8Array(leaf), new Uint8Array(key.getPublicKey().toDer()));
}

/** Constant-shape byte-array equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Encodes a Uint8Array to a base64 string.
 * @param bytes - The bytes to encode.
 */

/**
 * Decodes a base64 string to a Uint8Array.
 * @param str - The base64-encoded string.
 */

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

/** When a chain stops being usable, which for a session chain is the session's end. */
function earliestExpiryMs(chain: DelegationChain): number {
  const expirations = chain.delegations.map(({ delegation }) => delegation.expiration);
  if (expirations.length === 0) return 0;
  return Number(expirations.reduce((a, b) => (a < b ? a : b)) / 1_000_000n);
}

/**
 * Whether two sessions are the same one.
 *
 * Compared by chain, since a sign-in mints a fresh one: the account key is equal
 * for every session at the same account and says nothing about which this is.
 */
function isSameSession(a: Session, b: Session): boolean {
  return JSON.stringify(a.chain.toJSON()) === JSON.stringify(b.chain.toJSON());
}
