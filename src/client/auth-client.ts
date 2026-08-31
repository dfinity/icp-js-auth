import {
  AnonymousIdentity,
  type DerEncodedPublicKey,
  type HttpAgentOptions,
  type Identity,
  type SignIdentity,
} from '@icp-sdk/core/agent';
import {
  type DelegationChain,
  isDelegationValid,
  type PartialIdentity,
} from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { Signer } from '@icp-sdk/signer';
import { PostMessageTransport, UrlTransport } from '@icp-sdk/signer/web';
import { stealMintLock } from './app-lock.js';
import { fromBase64, toBase64 } from './base64.js';
import type { Credential, CredentialStorage } from './credential-storage.js';
import { watchActivity, watchForeground } from './foreground-refresh.js';
import { IdbCredentialStorage } from './idb-credential-storage.js';
import { IdleManager, type IdleManagerOptions } from './idle-manager.js';
import { requestSessionDelegation } from './session-delegation.js';
import { SessionIdentity } from './session-identity.js';
import { SessionMinter } from './session-minter.js';
import { type Slots, slotsFor } from './slots.js';
import { LocalStateStorage, type StateStorage } from './state-storage.js';

const NANOSECONDS_PER_SECOND = BigInt(1_000_000_000);
const SECONDS_PER_HOUR = BigInt(3_600);
const NANOSECONDS_PER_HOUR = NANOSECONDS_PER_SECOND * SECONDS_PER_HOUR;

const IDENTITY_PROVIDER_DEFAULT = 'https://id.ai/authorize';
const IDENTITY_CANISTER_DEFAULT = 'rdmx6-jaaaa-aaaaa-aaadq-cai';
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
   * Prefix for every slot this client writes under.
   *
   * Slots are assigned in one place rather than defaulted by each store, and this
   * moves all of them at once — so an application running two clients under one
   * origin separates them with a single string and cannot rename some while
   * missing others.
   *
   * Leave it unset unless a second client shares this origin.
   */
  namespace?: string;

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
   *
   * The default callback signs out and reloads, which since sessions also ends
   * the session at the canister — so an idle timeout is a full sign-out and not
   * merely a local one. Replace it with `onIdle`, or turn it off with
   * `disableDefaultIdleCallback`, where that is more than an application wants.
   *
   * Idleness is measured across the tabs of this origin, so the timeout is
   * reached only where none of them has been used.
   * @default after 10 minutes with no tab of this origin used, signs out and reloads
   */
  idleOptions?: IdleOptions;

  /**
   * Disables refreshing when the page is shown or the window regains focus.
   *
   * A backgrounded tab has its timers throttled, so its delegation can lapse
   * while nobody is looking and the first click after coming back waits for a
   * mint. Returning to the tab is early enough to hide that. Turn it off to make
   * requests the only thing that ever triggers one.
   * @default false
   */
  disableForegroundRefresh?: boolean;

  /**
   * Where the identity provider is, as two values rather than one.
   *
   * A ceremony is rendered at a URL and delegations are minted by a canister,
   * and they are not the same address: a custom domain can front the mainnet
   * canister, and a local deployment changes both. Each half defaults to its
   * mainnet value, so an application deploying against mainnet configures
   * neither. Nothing is derived from the URL — the origin of one is not a
   * promise about which canister answers there.
   */
  identityProvider?: {
    /** The authorize URL a ceremony is rendered at. */
    authorizeUrl?: string | URL;

    /** The canister that mints and revokes this application's delegations. */
    canisterId?: Principal | string;
  };

  /**
   * Options for the agent that makes the mint and revoke calls.
   *
   * `identity` is not among them: the agent signs as the session, which is what
   * those calls rest on.
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
   * The longest the session may last, in nanoseconds.
   *
   * A ceiling rather than a request: what the user chooses at consent wins over
   * it, an organization's cap narrows it further, and the canister clamps the
   * result to between 10 minutes and 30 days.
   *
   * The default is what this option defaulted to when it capped a delegation
   * rather than a session, kept so that no existing sign-in grows longer on
   * upgrade. It is expected to rise in a later release.
   * @default 8 hours
   */
  maxTimeToLive?: bigint;

  /**
   * The longest the session may outlive its use, in nanoseconds.
   *
   * The identity provider ends a session nothing has minted from for this long,
   * whatever {@link maxTimeToLive} still allows. It is what makes an abandoned
   * browser stop holding a usable sign-in, and it replaces the timer this
   * library used to run in the page: a timer is skipped by clearing storage or
   * by a tab that never runs it, and it saw one document, so a backgrounded tab
   * could sign a user out of the tab beside it.
   *
   * A ceiling in the same way {@link maxTimeToLive} is: the canister clamps it
   * to between 10 minutes and the session's own granted length, and applies its
   * own default of seven days where a request names none. The floor keeps clear
   * of the interval an active application mints at.
   *
   * Activity in the page counts as use, so a user reading rather than clicking
   * still keeps the session alive.
   * @default the identity provider's, currently 7 days
   */
  maxTimeToIdle?: bigint;

  /**
   * Where to go once the sign-in completes, ignored unless it is a same-origin
   * `http(s)` target.
   *
   * For the flow that leaves the page: a redirect sign-in comes back to whatever
   * URL the ceremony was started from, which is rarely where the user was. It is
   * journaled, so it survives the round trip, and the navigation replaces the
   * current history entry rather than adding one — the sign-in page and the
   * redirect chain are not somewhere a back button should return to.
   */
  returnTo?: string;
}

export interface SignedAttributes {
  data: Uint8Array;
  signature: Uint8Array;
}

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

/**
 * Manages authentication and identity for Internet Computer web apps.
 *
 * `getStatus()`, `isAuthenticated()` and `getPrincipal()` are synchronous, so a
 * page renders on them; `getIdentity()` is what an agent signs with.
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
  #credentialStorage: CredentialStorage;
  readonly #slots: Slots;
  readonly #canisterId: Principal;
  #unwatchForeground: (() => void) | undefined;
  #unwatchActivity: (() => void) | undefined;
  // `mousemove` fires by the dozen per second, and each call awaits a restore
  // before it can decide there is nothing to do. One at a time is enough: the
  // next event finds a fresher answer than the one already in flight anyway.
  #refreshingInForeground = false;
  #disposed = false;
  /** Ceremonies in flight, which suppress the foreground refresh. */
  #ceremonies = 0;
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
    this.#slots = slotsFor(options.namespace);
    this.#stateStorage = options.stateStorage ?? new LocalStateStorage(this.#slots.state);

    // A string or URL is what this option used to be, and a caller still passing
    // one would otherwise be silently ignored — both halves falling back to
    // mainnet, which is the kind of misconfiguration that only shows up as calls
    // going to the wrong canister.
    if (typeof options.identityProvider === 'string' || options.identityProvider instanceof URL) {
      throw new TypeError(
        'identityProvider is now an object: pass { authorizeUrl } for the ceremony URL, and { canisterId } for the canister that mints',
      );
    }

    this.#canisterId = Principal.from(
      options.identityProvider?.canisterId ?? IDENTITY_CANISTER_DEFAULT,
    );

    const identityProviderUrl = new URL(
      options.identityProvider?.authorizeUrl?.toString() || IDENTITY_PROVIDER_DEFAULT,
    );
    if (!options.disableForegroundRefresh) {
      // The identity decides whether a mint is due; these only say the moment is
      // a good one. Nothing is hooked where there is no DOM.
      //
      // The page arriving and the user using it are the same claim — somebody is
      // here — so both trigger the same refresh and one option governs both.
      const refresh = (): void => {
        void this.#refreshInForeground();
      };
      this.#unwatchForeground = watchForeground(refresh);
      this.#unwatchActivity = watchActivity(refresh);
    }
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
   * Releases what this client hooked: the foreground listeners, and the refresh
   * the identity has scheduled. Call it when discarding a client, so nothing it
   * registered outlives it.
   */
  dispose(): void {
    // Recorded, because the constructor starts the restore without awaiting it:
    // a client disposed while one is in flight would otherwise have an identity
    // installed afterwards, scheduling refreshes nobody can stop.
    this.#disposed = true;
    if (this.#identity instanceof SessionIdentity) this.#identity.dispose();
    this.#unwatchForeground?.();
    this.#unwatchForeground = undefined;
    this.#unwatchActivity?.();
    this.#unwatchActivity = undefined;
  }

  /**
   * Opens the identity provider, requests a delegation, and returns the authenticated identity.
   *
   * @param options - Sign-in options.
   * @param options.maxTimeToLive - Maximum lifetime of the delegation in nanoseconds.
   * @param options.maxTimeToIdle - How long the session may go unminted before the
   *   identity provider ends it, in nanoseconds.
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
    // A ceremony backgrounds this tab and foregrounds it again on its way back,
    // so without this the return fires a foreground refresh against the identity
    // this call is in the middle of replacing: a mint spent on a session being
    // discarded, and written to the store as though it were current.
    this.#ceremonies += 1;
    try {
      return await this.#runSignIn(options);
    } finally {
      this.#ceremonies -= 1;
    }
  }

  async #runSignIn(options?: AuthClientSignInOptions): Promise<Identity> {
    const maxTimeToLive = options?.maxTimeToLive ?? DEFAULT_MAX_TIME_TO_LIVE;

    // Journaled first, so a redirect flow finds it on the load that comes back:
    // the ceremony returns to the URL it was started from, which is rarely where
    // the user was. Journaled only when the caller gave one, so the journal of a
    // flow that omits it is unchanged.
    //
    // Validated inside the producer, so what is written down is an already-safe
    // href or nothing — never the raw value, which the journal would otherwise
    // carry across the round trip for the return leg to trust.
    const raw = options?.returnTo;
    const returnTo =
      raw === undefined ? undefined : this.memoize(() => sameOriginTarget(raw)?.href ?? null);

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

    if (!('sign' in key)) {
      // Unreachable for a typed caller, since `identity` is a SignIdentity.
      // Minting is a canister call signed by the session key, so a key that
      // cannot sign cannot hold a session, and failing here beats handing back
      // an identity whose first request fails for a reason nothing explains.
      throw new Error('A session needs a key that can sign');
    }

    const sessionChain = await requestSessionDelegation(this.#signer, {
      sessionPublicKey: key.getPublicKey().toDer(),
      maxTimeToLive,
      // Passed only where the caller asked, so the provider's own default is what
      // applies otherwise rather than a number this library invented.
      maxTimeToIdle: options?.maxTimeToIdle,
      derivationOrigin: this.#options.derivationOrigin?.toString(),
    });

    // The chain comes from the signer over a transport shared with others, so
    // the key it delegates to is checked here rather than assumed. A chain for
    // another key mints nothing, and failing now names the cause instead of
    // leaving it to the first request.
    if (!keyMatchesChain(key, sessionChain)) {
      throw new Error('The session chain does not delegate to the key it was requested for');
    }

    const idleOptions = this.#options?.idleOptions;
    if (!this.idleManager && !idleOptions?.disableIdle) {
      this.idleManager = IdleManager.create(idleOptions);
      this.#registerDefaultIdleCallback();
    }

    // Mint inside the ceremony the user is already waiting through, so the first
    // request after signing in does not wait. This is also where the account key
    // comes from: the session chain is rooted at the session's own key, and only
    // a mint reports the key an application's canisters will see.
    //
    // Into the ceremony's own slot, not the one every tab of this origin acts
    // with. Clearing that slot up front, or writing to it here, would change what
    // those tabs hold before this sign-in has succeeded — and a ceremony that
    // then failed would have cost each of them a mint for nothing.
    const minter = await this.#minterFor(key, sessionChain);
    const appKey = await this.#credentialStorage.create();
    const appChain = await minter.mint(appKey.getPublicKey().toDer());
    await this.#credentialStorage.set(this.#slots.appPending, {
      identity: appKey,
      chain: appChain,
    });

    // The session and the state first, because the state is what makes this
    // account the one this origin answers for; promoting ahead of it would
    // publish a credential for a sign-in nothing has recorded yet.
    await this.#persistSession(key, sessionChain, appChain.publicKey);
    await this.#promoteAppCredential();

    const identity = await this.#openSession(key, sessionChain, minter);
    this.#identity = identity;

    // Best-effort — the user is already signed in, so a cleanup failure must not
    // fail signIn(), and the next ceremony overwrites what is left behind.
    if (pending) {
      try {
        await this.#credentialStorage.remove(this.#slots.sessionPending);
      } catch {
        // ignore
      }
    }

    // Last, once the sign-in is stored, because this leaves the page: navigating
    // earlier would abandon the flow partway. Replaced rather than pushed, so the
    // sign-in page and the redirect chain are not what a back button returns to.
    // `await` above resolved the journaled value to a validated href or null.
    const target = await returnTo;
    if (typeof target === 'string') location.replace(target);

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
    // A redirect leaves the document, so the key this flow starts with has to be
    // readable again on the load that comes back. Two mediums answer for it: one
    // that survives the teardown, or one another tab can be asked. A store that
    // is neither cannot finish this flow, and refusing before navigating beats
    // sending the user to the identity provider and failing on their return.
    if (!this.#credentialStorage.durable && !this.#credentialStorage.shared) {
      throw new Error(
        'A redirect sign-in needs a credential store that survives the navigation or that another tab can answer for, and this one is neither. Use a durable store, a shared one, or the window transport.',
      );
    }

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
      const stored = await this.#credentialStorage.get(this.#slots.sessionPending);
      if (stored !== null) {
        acquired = stored.identity;
      } else {
        acquired = await this.#credentialStorage.create();
        await this.#credentialStorage.set(this.#slots.sessionPending, { identity: acquired });
      }
      return publicKeyOf(acquired);
    });

    const key: SignIdentity | PartialIdentity | null =
      acquired ?? (await this.#credentialStorage.get(this.#slots.sessionPending))?.identity ?? null;
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

    // Read before anything is cleared: the revoke call is made as the session,
    // so it needs what the wipe is about to remove.
    const session = await this.#credentialStorage.get(this.#slots.session).catch(() => null);

    // Taken away rather than queued for. Waiting would make a sign-out the user
    // asked for wait on a canister call in another tab; the tab that loses the
    // lock finishes the call it cannot recall, sees that it lost it, and throws
    // the result away rather than writing a credential into the slot cleared
    // below. Nothing holds the lock where no other tab can read the store.
    await stealMintLock(this.#credentialStorage.shared ? this.#slots.app : null);

    // Ending the session at the canister and clearing what is held here are
    // independent, so they run together: a slow or failing revoke must not hold
    // up a wipe the user asked for, and a user who pressed sign out must not
    // stay signed in on the device in front of them because a call failed.
    const revoked =
      session?.chain === undefined || !('sign' in session.identity)
        ? Promise.resolve()
        : this.#revoke(session.identity, session.chain).catch(() => undefined);
    const cleared = this.#endSession();

    if (this.#identity instanceof SessionIdentity) this.#identity.dispose();
    this.#identity = new AnonymousIdentity();

    // Only the wipe may fail the sign-out. The idle callback reloads on success
    // alone, and a reload after a failed wipe would restore the session it just
    // tried to end.
    await Promise.all([revoked, cleared]);

    if (options.returnTo !== undefined) {
      // The validated `href` reaches both sinks rather than the raw value, so
      // neither can be turned into an open redirect or a `javascript:` execution.
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

  /**
   * Mints ahead of the next request when the page comes back, if one is due.
   *
   * Silent by design: this is not a request anyone is waiting on, so a failure
   * leaves what is held in place for the next one to retry.
   */
  async #refreshInForeground(): Promise<void> {
    if (this.#ceremonies > 0 || this.#refreshingInForeground) return;
    this.#refreshingInForeground = true;
    try {
      await this.#refreshIfDue();
    } finally {
      this.#refreshingInForeground = false;
    }
  }

  async #refreshIfDue(): Promise<void> {
    // `pageshow` fires on the load itself, and this is what makes a page load
    // mint: without waiting for the restore, the load's own event finds an
    // anonymous identity and the first request pays for the mint instead.
    //
    // Nothing is waiting on this, so a restore that fails is not this path's to
    // report — and an unhandled rejection from an event handler is worse than
    // the mint it was going to attempt.
    const restored = await this.#init().then(
      () => true,
      () => false,
    );
    if (!restored) return;
    // Re-checked: a ceremony can start while the restore is resolving.
    if (this.#ceremonies > 0) return;
    const identity = this.#identity;
    if (identity instanceof SessionIdentity) await identity.refresh().catch(() => undefined);
  }

  /** Ends the session at the canister, so nothing more can be minted from it. */
  async #revoke(key: SignIdentity, sessionChain: DelegationChain): Promise<void> {
    const minter = await SessionMinter.create({
      sessionKey: key,
      sessionChain,
      canisterId: this.#canisterId,
      agentOptions: this.#options.agentOptions,
    });
    await minter.revoke();
  }

  /**
   * Moves what a ceremony minted into the slot every tab acts with.
   *
   * Overwrites rather than clearing and re-filling, so there is no moment where
   * the origin holds nothing — and what it replaces is a credential rooted at
   * whatever account the previous session belonged to.
   */
  async #promoteAppCredential(): Promise<void> {
    const minted = await this.#credentialStorage.get(this.#slots.appPending);
    if (minted?.chain === undefined) return;

    await this.#credentialStorage.set(this.#slots.app, {
      identity: minted.identity,
      chain: minted.chain,
    });
    // Best-effort: what is left behind is a spent five-minute record in a slot
    // nothing reads, replaced by the next ceremony.
    await this.#credentialStorage.remove(this.#slots.appPending).catch(() => undefined);
  }

  #minterFor(key: SignIdentity, sessionChain: DelegationChain): Promise<SessionMinter> {
    return SessionMinter.create({
      sessionKey: key,
      sessionChain,
      canisterId: this.#canisterId,
      agentOptions: this.#options.agentOptions,
    });
  }

  /**
   * Builds the identity an application acts with, from a session it holds.
   *
   * Little more than a constructor call: the identity resolves the account key it
   * needs, so this passes the session's own shape and the slot to use and nothing
   * more.
   * @param key - The session key, which signs the mints.
   * @param sessionChain - The chain that authorises it, and whose earliest
   *   delegation bounds how long anything can be minted.
   * @param source - A minter already built for this session, where the caller has
   *   one. A sign-in does; a page load does not.
   */
  async #openSession(
    key: SignIdentity,
    sessionChain: DelegationChain,
    source?: SessionMinter,
  ): Promise<SessionIdentity> {
    const minter = source ?? (await this.#minterFor(key, sessionChain));

    // The identity resolves its own account key, through the same locked
    // read-or-mint every rotation uses. Doing it here instead meant a second
    // writer of the app slot that took no lock: a load could overwrite a
    // credential a peer tab had just minted, and would not see the credential
    // that peer had left for it to adopt.
    return SessionIdentity.create({
      sessionExpiresAtMs: earliestExpiryMs(sessionChain),
      source: minter,
      storage: this.#credentialStorage,
      slot: this.#slots.app,
      onSessionGone: () => {
        // Drops what this origin holds and leaves the record standing: a dead
        // chain can mean a sibling replaced the session rather than that it ended.
        void this.#dropSession().catch(() => undefined);
        this.#identity = new AnonymousIdentity();
      },
    });
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

    if (!('sign' in key)) return;

    const identity = await this.#openSession(key, chain);
    if (this.#disposed) {
      // Disposed while this was in flight: install nothing, and stop the refresh
      // this identity has already scheduled for itself.
      identity.dispose();
      return;
    }
    this.#identity = identity;

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
    accountKey: DerEncodedPublicKey,
  ): Promise<void> {
    // A PartialIdentity is the caller's own and cannot sign, so there is nothing
    // worth storing: the client uses it for this run and restores nothing later.
    if (!('toDer' in identity)) {
      await this.#credentialStorage.set(this.#slots.session, { identity, chain });
    }

    let earliest: bigint | null = null;
    for (const { delegation } of chain.delegations) {
      if (earliest === null || delegation.expiration < earliest) {
        earliest = delegation.expiration;
      }
    }
    if (earliest !== null) {
      // The account is what a mint reported, and the sign-in lasts as long as
      // the session chain's earliest delegation.
      this.#stateStorage.set({
        principal: Principal.selfAuthenticating(new Uint8Array(accountKey)),
        expiration: earliest,
      });
    }
  }

  /**
   * Loads the stored session. Returns `null` and ends the sign-in where the
   * delegation has expired or the record cannot be read.
   */
  async #restoreSession(): Promise<Credential | null> {
    const credential = await this.#credentialStorage.get(this.#slots.session);
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
    this.#stateStorage.discard();
    await this.#clearCredentials();
  }

  // Always every slot, so no caller can end a sign-in halfway by naming one. The
  // state is retracted before this by both callers: it is what says whether this
  // origin is signed in, and a teardown that failed partway must not leave it
  // saying yes.
  //
  // Both are attempted whatever either does, since a credential that survives can
  // still be adopted; the first failure is reported once neither is left behind.
  async #clearCredentials(): Promise<void> {
    const outcomes = await Promise.allSettled([
      this.#credentialStorage.remove(this.#slots.session),
      this.#credentialStorage.remove(this.#slots.app),
    ]);
    const failed = outcomes.find((outcome) => outcome.status === 'rejected');
    if (failed !== undefined) throw failed.reason;
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

/** The moment a chain stops being usable: its earliest delegation's expiry. */
function earliestExpiryMs(chain: DelegationChain): number {
  let earliest: bigint | null = null;
  for (const { delegation } of chain.delegations) {
    if (earliest === null || delegation.expiration < earliest) {
      earliest = delegation.expiration;
    }
  }
  return earliest === null ? 0 : Number(earliest / 1_000_000n);
}

/** Whether a chain's leaf authorises the key it was requested for. */
function keyMatchesChain(key: SignIdentity | PartialIdentity, chain: DelegationChain): boolean {
  const leaf = chain.delegations[chain.delegations.length - 1]?.delegation.pubkey;
  if (leaf === undefined) return false;
  return publicKeyOf(key) === toBase64(new Uint8Array(leaf));
}

/** A key's public half as text, for comparing two keys without holding both. */
function publicKeyOf(key: SignIdentity | PartialIdentity): string {
  return toBase64(new Uint8Array(key.getPublicKey().toDer()));
}

/**
 * The `returnTo` as a URL this origin may navigate to, or `undefined`.
 *
 * Same-origin and `http(s)` only. Anything else is ignored rather than refused,
 * because a `returnTo` is a convenience and failing a sign-in or a sign-out over
 * one would be worse than landing on the page the caller started from. Returning
 * the parsed URL rather than a boolean is what lets callers navigate to
 * `target.href` instead of to the raw value they were handed.
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
