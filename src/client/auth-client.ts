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
import { AccountMismatchError, chainAuthorisesKey } from './app-delegation-source.js';
import { type HeldLock, stealLock, stealMintLock } from './app-lock.js';
import { fromBase64, toBase64 } from './base64.js';
import type { Credential, CredentialStorage } from './credential-storage.js';
import { watchActivity, watchForeground } from './foreground-refresh.js';
import { IdbCredentialStorage } from './idb-credential-storage.js';
import { requestSessionDelegation } from './session-delegation.js';
import { SessionIdentity } from './session-identity.js';
import { SessionMinter } from './session-minter.js';
import { type Slots, slotsFor } from './slots.js';
import { normalizeSsoDomain } from './sso.js';
import { LocalStateStorage, type SessionState, type StateStorage } from './state-storage.js';

/**
 * The lock one signer interaction at a time holds.
 *
 * Per origin rather than per namespace, because what cannot be shared is not
 * namespaced: an origin has one signer window — `${origin}-signer-window` — and
 * one redirect journal per route. Two clients in different namespaces are two
 * sign-ins, and they still cannot both have the window.
 */
const CHANNEL_LOCK = 'ic-auth-signer-channel';

/** The lock over one namespace's sign-in, which `signIn` and `signOut` both move. */
const signInLockFor = (stateSlot: string): string => `${stateSlot}:sign-in`;

const IDENTITY_PROVIDER_DEFAULT = 'https://id.ai/authorize';
const IDENTITY_CANISTER_DEFAULT = 'rdmx6-jaaaa-aaaaa-aaadq-cai';

export type OpenIdProvider = 'google' | 'apple' | 'microsoft';

export const OPENID_PROVIDER_URLS = {
  google: 'https://accounts.google.com',
  apple: 'https://appleid.apple.com',
  microsoft: 'https://login.microsoftonline.com/{tid}/v2.0',
} as const satisfies Record<OpenIdProvider, string>;

const DEFAULT_OPENID_SCOPE_KEYS = ['name', 'email', 'verified_email'] as const;

const DEFAULT_SSO_SCOPE_KEYS = ['name', 'email'] as const;

/**
 * Options for creating an {@link AuthClient}, other than the one-click sign-in
 * entry point. See {@link AuthClientCreateOptions}.
 */
export interface AuthClientBaseOptions {
  /**
   * Where credentials are kept. Defaults to IndexedDB.
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
   */
  stateStorage?: StateStorage;

  /**
   * Stops this client from watching the browser for signs that somebody is here.
   *
   * All of them together, because they make one claim: the page being shown, the
   * window regaining focus, a pointer or a key. A backgrounded tab has its timers
   * throttled, so its delegation can lapse while nobody is looking and the first
   * click after coming back waits for a mint; returning to the tab is early
   * enough to hide that.
   *
   * Nothing is hooked where there is no DOM, so a client outside a browser needs
   * no option. Setting it makes requests the only thing that says this session is
   * in use — including to the identity provider, which ends a session nothing
   * has minted from for long enough. An application whose users read more than
   * they click should leave it alone.
   * @default false
   */
  disableBrowserActivity?: boolean;

  /**
   * Where the identity provider is, as two values rather than one.
   *
   * A ceremony is rendered at a URL and delegations are minted by a canister,
   * and they are not the same address: a custom domain can front the mainnet
   * canister, and a local deployment changes both. Nothing is derived from the
   * URL — the origin of one is not a promise about which canister answers
   * there — so a deployment is named by both or by neither. Omit the option and
   * both are mainnet's.
   */
  identityProvider?: {
    /** The authorize URL a ceremony is rendered at. */
    authorizeUrl: string | URL;

    /** The canister that mints and revokes this application's delegations. */
    canisterId: Principal | string;
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
   * Whether Internet Identity may answer without user interaction.
   *
   * - `'login'` (the effect of omitting it): run a normal sign-in ceremony.
   * - `'none'`: Internet Identity answers from a session it already holds for
   *   this app and returns without rendering anything, or fails with an
   *   `interaction_required` error if it cannot. Pair with {@link hint} to name
   *   which account to re-issue for. Use it on a page load where the state names
   *   an account this origin has no credentials for — a sibling subdomain signed
   *   in — so this origin acquires its own without a ceremony.
   *
   * Sent as a `prompt` query param on the authorize URL. An Internet Identity
   * extension inspired by OpenID Connect's `prompt`, and not part of any ICRC
   * standard — which is why it travels on the URL rather than in the request.
   */
  prompt?: 'none' | 'login';

  /**
   * The account to re-issue for, which is the principal the state names.
   *
   * Sent as text in a `hint` query param on the authorize URL; Internet Identity
   * uses it to pick which session a {@link prompt} `'none'` request resolves to
   * when the user has more than one for this app. Inspired by OpenID Connect's
   * `login_hint`.
   */
  hint?: Principal;

  /**
   * Whether Internet Identity may keep this sign-in so that a later
   * {@link prompt} `'none'` request can be answered from it.
   *
   * Defaults to what {@link AuthClientCreateOptions.stateStorage} says, which is
   * `true` only for {@link CookieStateStorage}: an application declares this
   * intent by choosing a store whose record reaches its siblings, and making it
   * say so a second time would be noise. Set it here for a cross-origin
   * arrangement that is not sibling subdomains, or to force it off for siblings
   * that should each sign in properly.
   *
   * Off means the provider keeps no session for this app on this device, so
   * there is nothing for a silent request to find. It says nothing about how
   * long a session lasts: {@link AuthClientSignInOptions.maxTimeToIdle} applies
   * either way.
   *
   * Sent as a `resumable` query param on the authorize URL, for the same reason
   * {@link prompt} is: the URL is assembled once, here.
   */
  resumable?: boolean;
}

/**
 * Options for creating an {@link AuthClient}.
 *
 * At most one one-click sign-in entry point may be set: `openIdProvider` for a
 * hardcoded provider, or `ssoDomain` for an organization's own SSO.
 */
export type AuthClientCreateOptions = AuthClientBaseOptions &
  (
    | {
        /**
         * OpenID provider for one-click sign-in. When set, the identity provider
         * URL includes an `openid` search param so the user authenticates via
         * the chosen provider (e.g. Google) instead of seeing Internet Identity directly.
         */
        openIdProvider?: OpenIdProvider;
        ssoDomain?: never;
      }
    | {
        openIdProvider?: never;
        /**
         * Organization domain for one-click SSO sign-in, e.g. `'dfinity.org'`.
         * When set, the identity provider URL includes an `sso` search param so
         * the user authenticates via that organization's own provider.
         *
         * A value that is not a domain with an optional port throws. Use
         * {@link isValidSsoDomain} to check a domain the user typed.
         */
        ssoDomain?: string;
      }
  );

/**
 * Options for {@link AuthClient.signIn}.
 */
export interface AuthClientSignInOptions {
  /**
   * The longest the session may last, in nanoseconds.
   * @default the identity provider's, currently 30 days
   */
  maxTimeToLive?: bigint;

  /**
   * How long a signed-in user may be idle before the sign-in ends, in nanoseconds.
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
 * Who is signed in for this origin, and until when.
 *
 * `principal` and `expiresAtMs` are present in every case where a record
 * exists, so an application can name the account and count down to the end of a
 * sign-in without reading the store itself.
 */
export type SessionStatus =
  | { state: 'signed-in'; principal: Principal; expiresAtMs: number }
  /**
   * Someone is signed in on this domain, but this origin holds no credential
   * for them, so it cannot act yet. Acquire one silently, or ask the user.
   */
  | { state: 'signed-in-elsewhere'; principal: Principal; expiresAtMs: number }
  | { state: 'expired'; principal: Principal; expiresAtMs: number }
  | { state: 'signed-out' };

/**
 * Thrown when a sign-in exists within the state store's reach but this origin
 * holds no credential for it.
 *
 * A sibling subdomain reads the shared record on its first load and is in exactly
 * this position: someone is signed in, and it has nothing to act with until it
 * acquires its own. Catching this is where a silent re-issue belongs.
 */
export class SessionNotHeldError extends Error {
  constructor(
    message = 'A sign-in exists for this domain, but this origin holds no credential for it',
  ) {
    super(message);
    this.name = 'SessionNotHeldError';
  }
}

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
/**
 * Thrown when a later sign-in or sign-out took over from this one.
 *
 * Not a failure of the operation so much as a change of mind: an origin has one
 * signer window and one sign-in, so the newer intent is the one honoured, and
 * the earlier one reports this rather than writing what it had assembled. A
 * caller may usually ignore it — the user is getting what they asked for second.
 */
export class SupersededError extends Error {
  constructor(message = 'A later sign-in or sign-out took over from this one') {
    super(message);
    this.name = 'SupersededError';
  }
}

export class AuthClient {
  #identity: Identity | PartialIdentity = new AnonymousIdentity();
  #credentialStorage: CredentialStorage;
  readonly #slots: Slots;
  readonly #canisterId: Principal;
  #unwatchForeground: (() => void) | undefined;
  #unwatchState: (() => void) | undefined;
  #unwatchActivity: (() => void) | undefined;
  // `mousemove` fires by the dozen per second, and each call awaits a restore
  // before it can decide there is nothing to do. One at a time is enough: the
  // next event finds a fresher answer than the one already in flight anyway.
  #refreshingInForeground = false;
  #disposed = false;
  // Set while a further restore is pending, so a burst of changes is one pass.
  #restoreQueued = false;
  // What `getStatus` answers with, replaced only when the record changes.
  #status: SessionStatus;
  readonly #listeners = new Set<() => void>();
  // Set while a restore is running, so its own writes are not news.
  #restoring = false;
  #stateStorage: StateStorage;
  #signer: Signer;
  // Set only in redirect mode, so the redirect-specific paths (nonce/key
  // journaling) can reach `memoize`. Undefined in the default 'window' mode.
  #urlTransport: UrlTransport | undefined;
  #options: AuthClientCreateOptions;
  #initPromise: Promise<void> | null = null;
  // Signer interactions this client has in flight. One lock covers all of them:
  // `signIn` and `requestAttributes` overlapped share a channel on purpose, and
  // the channel closes when the last request settles, so they are one
  // interaction rather than two.
  #interactions = 0;
  #channelLock: HeldLock | undefined;

  constructor(options: AuthClientCreateOptions = {}) {
    this.#options = options;
    this.#credentialStorage = options.credentialStorage ?? new IdbCredentialStorage();
    this.#slots = slotsFor(options.namespace);
    this.#stateStorage = options.stateStorage ?? new LocalStateStorage();

    // A string or URL is what this option used to be, and a caller still passing
    // one would otherwise be silently ignored — both halves falling back to
    // mainnet, which is the kind of misconfiguration that only shows up as calls
    // going to the wrong canister.
    if (typeof options.identityProvider === 'string' || options.identityProvider instanceof URL) {
      throw new TypeError(
        'identityProvider is now an object: pass { authorizeUrl, canisterId } — the URL a ceremony is rendered at, and the canister that mints',
      );
    }

    const provider = options.identityProvider ?? {
      authorizeUrl: IDENTITY_PROVIDER_DEFAULT,
      canisterId: IDENTITY_CANISTER_DEFAULT,
    };

    // Both or neither, for the same reason a bare URL is refused above: half of
    // a deployment renders the ceremony at one provider and mints against
    // another. The type says so, and this says it to a caller without one.
    if (provider.authorizeUrl === undefined || provider.canisterId === undefined) {
      throw new TypeError(
        'identityProvider names authorizeUrl and canisterId together, or neither: nothing about the canister is derived from the URL',
      );
    }

    this.#canisterId = Principal.from(provider.canisterId);

    const identityProviderUrl = new URL(provider.authorizeUrl.toString());
    if (!options.disableBrowserActivity) {
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

    // The third outside signal, and the one that is not about a moment being a
    // good one: the record can be replaced under this client — by a peer client
    // on this page sharing its stores, or by another tab — and nothing about a
    // restore already done reflects that. Hooked whatever
    // `disableBrowserActivity` says, because it is not a refresh: a client
    // answering for a sign-in the record no longer names is wrong rather than
    // stale.
    this.#status = this.#readStatus();
    this.#unwatchState = this.#stateStorage.subscribe(this.#slots.state, () => {
      // The held answer first, then the listeners, then whatever this client has
      // to do about it — so a listener asking who is signed in sees what it was
      // told about, whether or not the guard below lets a restore run.
      this.#status = this.#readStatus();
      for (const listener of [...this.#listeners]) listener();

      // Only a change this client did not cause. A ceremony writes this record
      // itself and installs the identity that goes with it, and a restore writes
      // it too when what it found turns out not to be usable — reacting to
      // either would re-hydrate mid-ceremony, when the app slot still holds the
      // previous account's credential. The same reason the foreground refresh
      // stands down for a ceremony.
      //
      // What this gives up is a peer's change arriving during our own restore,
      // which the next change reports.
      if (this.#interactions > 0 || this.#restoring || this.#disposed) return;
      this.#restoreAgain();
    });
    if (options.openIdProvider !== undefined && options.ssoDomain !== undefined) {
      throw new Error('openIdProvider and ssoDomain are mutually exclusive');
    }
    if (options.openIdProvider) {
      identityProviderUrl.searchParams.set('openid', OPENID_PROVIDER_URLS[options.openIdProvider]);
    }
    if (options.ssoDomain !== undefined) {
      identityProviderUrl.searchParams.set('sso', normalizeSsoDomain(options.ssoDomain));
      // The SSO ceremony starts before a delegation is requested, so the
      // channel carries the derivation origin too late to resolve the client.
      if (options.derivationOrigin !== undefined) {
        identityProviderUrl.searchParams.set(
          'derivationOrigin',
          options.derivationOrigin.toString(),
        );
      }
    }
    // `prompt` and `hint` are Internet Identity extensions, so they ride on the
    // authorize URL rather than in the ICRC request. Baking them in here, as
    // `openid` is, means a client is configured for one authorize intent —
    // construct a separate client for a silent re-issue and for an interactive
    // sign-in. Both share this client's storage, so whichever resolves populates
    // the same session.
    if (options.prompt) {
      identityProviderUrl.searchParams.set('prompt', options.prompt);
    }
    if (options.hint) {
      identityProviderUrl.searchParams.set('hint', options.hint.toText());
    }
    // The store already carries the intent, so the option only has to override
    // it. Written only when true: absent is what the provider reads as "keep
    // nothing", and an explicit `false` would say the same thing louder.
    if (options.resumable ?? this.#stateStorage.resumable ?? false) {
      identityProviderUrl.searchParams.set('resumable', 'true');
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

    // Eagerly start restoring a previous session from storage.
    // The result is awaited in getIdentity() before returning.
    this.#init();
  }

  /**
   * Returns the current identity, restoring a previous session if available.
   */
  async getIdentity(): Promise<Identity> {
    await this.#init();

    // A record exists and this client holds nothing to act with. Handing back an
    // anonymous identity here is the dangerous answer: calls would go out
    // unauthenticated while `isAuthenticated()` and the record both say someone
    // is signed in. Failing by name is what lets a caller acquire one.
    //
    // Any record, not only one this origin does not hold. A sibling subdomain
    // arriving without a credential is the case this was written for, and it is
    // not the only way to get here: a store that cannot report a change — or
    // reports it wrongly — leaves this client on an answer the record has moved
    // past, and `held` is `true` for every record a same-origin store keeps, so
    // asking about it would have let exactly that through.
    //
    // A disposed client is exempt: it holds nothing because it was told to stop,
    // which is not the same as being unable to act on a sign-in that exists.
    const state = this.#stateStorage.get(this.#slots.state);
    if (state !== null && !this.#disposed && this.#identity instanceof AnonymousIdentity) {
      throw new SessionNotHeldError();
    }
    return this.#identity;
  }

  /**
   * Checks whether the user has an active, non-expired session.
   */
  isAuthenticated(): boolean {
    return this.getStatus().state === 'signed-in';
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
    return status.state === 'signed-in' ? status.principal : undefined;
  }

  /**
   * Who is signed in for this origin right now.
   *
   * Synchronous, so a page can render on it without opening a store.
   */
  getStatus(): SessionStatus {
    // The same object until something actually changes. A page renders on this,
    // and a framework asking "did it change?" compares the object rather than
    // its contents — a fresh one per call reads as a change on every render, and
    // `useSyncExternalStore` refuses a snapshot that never settles. Returning
    // the held one also means no `Principal.fromText` per call.
    //
    // Expiry is the one transition with no write behind it, so it is the one
    // thing checked here: a number comparison, and the answer is rebuilt once
    // when it flips.
    if (this.#status.state !== 'signed-out' && Date.now() >= this.#status.expiresAtMs) {
      if (this.#status.state !== 'expired') {
        const { principal, expiresAtMs } = this.#status;
        this.#status = { state: 'expired', principal, expiresAtMs };
      }
    }
    return this.#status;
  }

  /** Reads the record and builds the answer `getStatus` hands out. */
  #readStatus(): SessionStatus {
    const record = this.#stateStorage.get(this.#slots.state);
    if (record === null) return { state: 'signed-out' };

    const { principal } = record;
    const expiresAtMs = Number(record.expiration / 1_000_000n);
    if (Date.now() >= expiresAtMs) {
      return { state: 'expired', principal, expiresAtMs };
    }
    return record.held
      ? { state: 'signed-in', principal, expiresAtMs }
      : { state: 'signed-in-elsewhere', principal, expiresAtMs };
  }

  /**
   * Watches who is signed in here, and returns a function that stops watching.
   *
   * `getStatus()` and the predicates beside it are snapshots, so an application
   * rendering on them needs to be told when to read again. The record changes
   * for reasons that are nothing to do with this client — another tab signing
   * out, a sibling subdomain publishing a sign-in, a peer client on this page
   * re-issuing silently — and this is how those arrive.
   *
   * Fired once the record is readable, so a listener asking who is signed in
   * sees what it was told about. It says that something changed and not what: a
   * listener reads the answer it wants, which for most is `getStatus()`.
   *
   * What it does not cover is the identity being replaced under an application
   * that holds one — an app delegation rotating is deliberately invisible, and
   * nothing about who is signed in has changed when it does.
   * @param listener - Called after the record changes.
   * @returns A function that unregisters it.
   */
  subscribe(listener: () => void): () => void {
    // Fired by this client rather than by the store, because the answer has to
    // be up to date before a listener asks for it: the store announcing first
    // would let a listener read a status one change behind.
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  /**
   * Releases what this client hooked: the browser listeners, the state
   * subscription, and the refresh the identity has scheduled. Call it when
   * discarding a client, so nothing it registered outlives it.
   */
  dispose(): void {
    // Recorded, because the constructor starts the restore without awaiting it:
    // a client disposed while one is in flight would otherwise have an identity
    // installed afterwards, scheduling refreshes nobody can stop.
    this.#disposed = true;
    if (this.#identity instanceof SessionIdentity) this.#identity.dispose();
    // Its own interaction and no one else's: the locks it holds are released
    // rather than taken, its own channel is closed, and nothing shared is
    // written. Disposing means stop using this client, not sign out — another
    // instance may be acting on the same slots.
    //
    // Fired rather than awaited, because this stays synchronous: an application
    // discarding a client has nothing to do with the answer.
    if (this.#interactions > 0) {
      void this.#signer.closeChannel().catch(() => undefined);
    }
    this.#channelLock?.release();
    this.#channelLock = undefined;
    this.#unwatchForeground?.();
    this.#unwatchForeground = undefined;
    this.#unwatchActivity?.();
    this.#unwatchActivity = undefined;
    this.#unwatchState?.();
    this.#unwatchState = undefined;
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
  /**
   * Records that an interaction is under way, without asking the browser for
   * anything.
   *
   * Separate from taking the lock because of when each may happen: the count has
   * to be up before the first await, and a lock may only be asked for once the
   * signer window is open.
   */
  /**
   * Installs the identity this client acts with, releasing the one it replaces.
   *
   * A {@link SessionIdentity} holds a scheduled refresh, so dropping the
   * reference without disposing leaves a timer that can still mint — into a slot
   * this client may no longer be the writer of, for a session it may no longer
   * hold. Every assignment goes through here so that no path can forget, which
   * matters most for the paths that give up rather than the ones that succeed:
   * those are the paths written to stop acting.
   */
  #installIdentity(next: Identity | PartialIdentity): void {
    const previous = this.#identity;
    if (previous !== next && previous instanceof SessionIdentity) previous.dispose();
    this.#identity = next;
  }

  #beginInteraction(): void {
    this.#interactions += 1;
  }

  /**
   * Opens the signer channel and takes the lock that makes this the only
   * interaction on it.
   *
   * One method because the order is the whole point. A popup may only be opened
   * from the task the click started, so nothing may be asked of the browser
   * before `openChannel` — two lock requests in front of it were enough for
   * Chromium to refuse the window — and the lock has to be taken as soon as it
   * is open. Two callers doing that by hand is one place too many for the order
   * to come out backwards.
   */
  async #openSignerChannel(): Promise<void> {
    await this.#signer.openChannel();

    if (this.#channelLock === undefined) {
      const lock = stealLock(CHANNEL_LOCK);
      // Whoever took the channel has already renavigated the window this one was
      // talking to, so its requests will never be answered. Closing it is what
      // turns waiting forever into failing, and it releases the window for the
      // interaction that took over.
      lock.stolen.addEventListener(
        'abort',
        () => {
          void this.#signer.closeChannel().catch(() => undefined);
        },
        { once: true },
      );
      this.#channelLock = lock;
    }
  }

  #endInteraction(): void {
    this.#interactions -= 1;
    if (this.#interactions === 0) {
      this.#channelLock?.release();
      this.#channelLock = undefined;
    }
  }

  /**
   * Refuses to go on where this operation is no longer the current one.
   *
   * Asked after the calls have returned and before anything shared is written,
   * which is where `acquireCredential` asks it for a mint and for the same
   * reason: a call already sent cannot be recalled, so the only thing left to
   * decide is whether to keep its result.
   */
  #assertCurrent(signInLock: HeldLock): void {
    if (this.#disposed) {
      throw new SupersededError('This client was disposed while signing in');
    }
    if (this.#channelLock?.stolen.aborted === true) {
      throw new SupersededError('Another signer interaction took the channel');
    }
    if (signInLock.stolen.aborted) {
      throw new SupersededError();
    }
  }

  async signIn(options?: AuthClientSignInOptions): Promise<Identity> {
    // Counted here and locked inside, once the window is open: a ceremony is
    // both things — the signer channel an origin has one of, and this
    // namespace's sign-in, which `signOut` moves too — but neither lock may be
    // asked for before the popup exists.
    //
    // The count is also what stands the foreground refresh down: a ceremony
    // backgrounds this tab and foregrounds it again on its way back, so without
    // it the return fires a refresh against the identity this call is in the
    // middle of replacing — a mint spent on a session being discarded, and
    // written to the store as though it were current. It asks the browser for
    // nothing, so it is safe to do first.
    this.#beginInteraction();
    try {
      return await this.#runSignIn(options);
    } finally {
      this.#endInteraction();
    }
  }

  async #runSignIn(options?: AuthClientSignInOptions): Promise<Identity> {
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

    // Must stay the first await: it opens the signer window, which the browser
    // allows only in the tick the click started.
    await this.#openSignerChannel();

    // The other lock a ceremony needs, taken once the window is open for the
    // same reason. Stolen rather than queued for, so the newer intent wins and
    // the loser learns of it before writing anything.
    //
    // A local, not a field: two overlapping calls would each write the field,
    // and then both the supersede check and the release would read whichever
    // wrote last — leaving the running call unlocked and unable to notice a
    // steal, while the stolen lock's own signal went to an object nothing held.
    const signInLock = stealLock(signInLockFor(this.#slots.state));

    // Every shared write goes through this. One check before the first write is
    // not enough: the lock reaches across tabs, so a sign-out can land between
    // any two of the writes below, clear the slots and the record, and this flow
    // would put them all back — signing the user out and straight back in.
    const guarded = async (write: () => Promise<void>): Promise<void> => {
      this.#assertCurrent(signInLock);
      await write();
    };

    // Released here rather than by the caller: the lock belongs to this call,
    // and a call that hands it to a field cannot tell its own from another's.
    try {
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
        // Both bounds are sent only where the caller asked, so the provider's
        // own defaults apply otherwise rather than numbers this library
        // invented. How long a sign-in lasts is the provider's policy, narrowed
        // by what the user chooses at consent and by an organization's cap.
        maxTimeToLive: options?.maxTimeToLive,
        maxTimeToIdle: options?.maxTimeToIdle,
        derivationOrigin: this.#options.derivationOrigin?.toString(),
      });

      // The chain comes from the signer over a transport shared with others, so
      // the key it delegates to is checked here rather than assumed. A chain for
      // another key mints nothing, and failing now names the cause instead of
      // leaving it to the first request.
      if (!chainAuthorisesKey(sessionChain, key.getPublicKey().toDer())) {
        throw new Error('The session chain does not delegate to the key it was requested for');
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

      // Everything above was a call, and none of it is shared; everything below is
      // a write four other things read.
      await guarded(() =>
        this.#credentialStorage.set(this.#slots.appPending, { identity: appKey, chain: appChain }),
      );

      // The session and the state first, because the state is what makes this
      // account the one this origin answers for; promoting ahead of it would
      // publish a credential for a sign-in nothing has recorded yet.
      await guarded(() => this.#persistSession(key, sessionChain, appChain.publicKey));
      await guarded(() => this.#promoteAppCredential(appKey, appChain));

      await guarded(async () => {
        this.#installIdentity(await this.#openSession(key, sessionChain, minter));
      });

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
    } finally {
      signInLock.release();
    }
  }

  // Window flow: sign-in completes in a single load, so a fresh session key per
  // sign-in is enough, with nothing to persist for a later load.
  #ensureSessionKeyForWindowFlow(): Promise<SignIdentity> {
    return this.#credentialStorage.create();
  }

  // Redirect flow: `signIn` runs twice — once on the load that navigates to the
  // identity provider, and again on the return load that replays the delegation
  // minted for the FIRST load's key. Both runs must therefore use the same key,
  // so the first load writes it to the pending slot and the return load reads it
  // back.
  async #ensureSessionKeyForRedirectFlow(
    transport: UrlTransport,
  ): Promise<{ key: SignIdentity; pending?: boolean }> {
    // A redirect leaves the document, so the key this flow starts with has to be
    // readable again on the load that comes back, which takes a medium that
    // survives the teardown. Refusing before navigating beats sending the user to
    // the identity provider and failing on their return.
    //
    // A store other tabs can read is not enough. It answers only while one of
    // them is open, so the same flow in the only tab of an origin loses the key
    // the moment it navigates — a rule that holds sometimes is worse than one
    // that holds never, because it fails on the user rather than on the
    // developer.
    if (!this.#credentialStorage.durable) {
      throw new Error(
        'A redirect sign-in needs a credential store that survives the navigation, and this one does not. Use a durable store or the window transport.',
      );
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
    // Empty or holding another flow's key: either way the key this ceremony
    // journaled is no longer in the slot, so the delegation being replayed was
    // minted for a key this flow does not have. The caller retries, and by then
    // the sign-in that superseded it has usually been promoted.
    if (key === null || publicKeyOf(key) !== startedWith) {
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
    // The channel lock and not the sign-in lock: this opens the signer channel,
    // which an origin has one of, and writes nothing anyone else reads. Held
    // together with a `signIn` overlapping it, which shares the same channel.
    this.#beginInteraction();
    try {
      return await this.#runRequestAttributes(params);
    } finally {
      this.#endInteraction();
    }
  }

  async #runRequestAttributes(params: {
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

    // The same lock a ceremony takes, and taken the same way: this is the other
    // operation that moves this namespace's sign-in. No channel lock — a revoke
    // is an agent call to the canister, so nothing here touches the signer.
    const signOutLock = stealLock(signInLockFor(this.#slots.state));

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
    //
    // A failed revoke is carried rather than thrown, so the wipe below still
    // finishes, and rather than dropped, so it can be raised once it has.
    const revoked: Promise<unknown> =
      session?.chain === undefined || !('sign' in session.identity)
        ? Promise.resolve(undefined)
        : this.#revoke(session.identity, session.chain).then(
            () => undefined,
            (error: unknown) => error,
          );
    const cleared = this.#endSession();

    this.#installIdentity(new AnonymousIdentity());

    const [revokeFailure] = await Promise.all([revoked, cleared]);

    signOutLock.release();

    // Raised after the wipe and before the navigation. The device is signed out
    // whatever happened at the canister, and an application that told a user it
    // had signed them out of their apps can find out that it had not — which it
    // could not if this were swallowed, and could not act on if it arrived after
    // the page had left.
    if (revokeFailure !== undefined) throw revokeFailure;

    if (options.returnTo !== undefined) {
      // A navigation rather than a `pushState`: nothing obliges an application to
      // re-render when the history entry changes — `pushState` fires no
      // `popstate` — so the signed-in view would sit under a signed-out URL. The
      // validated `href` is what reaches the sink rather than the raw value, so
      // neither an open redirect nor a `javascript:` execution can be built
      // from it.
      const target = sameOriginTarget(options.returnTo);
      if (target !== undefined) {
        window.location.assign(target.href);
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
    await this.#openSignerChannel();
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
    if (this.#interactions > 0 || this.#refreshingInForeground) return;
    this.#refreshingInForeground = true;
    try {
      await this.#refreshIfDue();
    } finally {
      this.#refreshingInForeground = false;
    }
  }

  async #refreshIfDue(): Promise<void> {
    // Waited for rather than raced: a `pageshow` or a pointer arriving before the
    // restore has installed an identity would find an anonymous one and do
    // nothing, and the moment would be spent. The restore mints on its own where
    // a load needs one, so what this adds is the page coming back from the
    // back-forward cache, and every later sign that somebody is here.
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
    if (this.#interactions > 0) return;
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
  async #promoteAppCredential(identity: SignIdentity, chain: DelegationChain): Promise<void> {
    // Written from what the ceremony minted rather than read back out of the
    // pending slot: a read that came back empty returned silently and left the
    // slot holding the previous account's credential, which the identity opened
    // on the next line would then adopt.
    await this.#credentialStorage.set(this.#slots.app, { identity, chain });
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

    // The account comes from the record, which both callers have already
    // written or checked: a ceremony persists the session before this runs, and
    // a restore refuses a record that names nobody. Without it the identity
    // would take its account from whatever the app slot held, which a previous
    // sign-in may still own.
    const held = this.#stateStorage.get(this.#slots.state);

    return SessionIdentity.create({
      sessionExpiresAtMs: earliestExpiryMs(sessionChain),
      source: minter,
      storage: this.#credentialStorage,
      slot: this.#slots.app,
      expectedAccount: held?.principal,
      onSessionGone: () => {
        void this.#endOrDrop(held).catch(() => undefined);
        this.#installIdentity(new AnonymousIdentity());
      },
    });
  }

  /**
   * Ends the sign-in, or only this origin's claim on it.
   *
   * A refused mint says the session this origin held is dead, and a domain has
   * one: it cannot be revived, only replaced. So if the record still names what
   * this origin was operating under — same account, same expiry — it names a
   * session nobody can use, and it goes. If it has moved on in either respect,
   * someone else owns the sign-in now and this origin converges to them rather
   * than retracting what they published.
   * @param held - The record as it stood when the session was opened.
   */
  async #endOrDrop(held: SessionState | null): Promise<void> {
    const now = this.#stateStorage.get(this.#slots.state);
    const unchanged =
      held !== null &&
      now !== null &&
      now.principal.compareTo(held.principal) === 'eq' &&
      now.expiration === held.expiration;
    await (unchanged ? this.#endSession() : this.#dropSession());
  }

  /**
   * Restores again, because the record changed under this client.
   *
   * Queued behind whatever restore is in flight rather than replacing it: two
   * restores reading one store would both install an identity, and the order
   * they finished in would decide which. A failure is forgotten the same way
   * {@link AuthClient.#init} forgets one, so the next call tries again.
   */
  #restoreAgain(): void {
    // Coalescing, not queueing: a pass that has not started yet will read the
    // same record a second one would, so any burst collapses to one more pass.
    // Each pass can install an identity, and installing disposes the one it
    // replaces — redundant passes mean disposing an identity with requests in
    // flight against it.
    if (this.#restoreQueued) return;
    this.#restoreQueued = true;

    const promise = (this.#initPromise ?? Promise.resolve())
      .catch(() => undefined)
      .then(() => {
        this.#restoreQueued = false;
        return this.#restore();
      })
      .catch((error: unknown) => {
        this.#restoreQueued = false;
        if (this.#initPromise === promise) {
          this.#initPromise = null;
        }
        throw error;
      });
    this.#initPromise = promise;
    // Nothing is waiting on this yet — the next `getIdentity()` is — so a
    // rejection here would be unhandled until then.
    promise.catch(() => undefined);
  }

  // Memoized — only runs #hydrate once, returns the same promise on repeat calls.
  //
  // Forgotten again if it rejected, so a later call restores rather than
  // replaying the failure: a restore reaches the network, and one unreachable
  // boundary node at load would otherwise leave every `getIdentity()` for the
  // life of the page rejecting with an error nothing can retry past.
  #init(): Promise<void> {
    if (!this.#initPromise) {
      const promise = this.#restore().catch((error: unknown) => {
        if (this.#initPromise === promise) {
          this.#initPromise = null;
        }
        throw error;
      });
      this.#initPromise = promise;
    }
    return this.#initPromise;
  }

  // Marks a restore as running, so what it writes does not come back as a
  // record that changed under this client.
  async #restore(): Promise<void> {
    this.#restoring = true;
    try {
      await this.#hydrate();
    } finally {
      this.#restoring = false;
    }
  }

  // Attempts to restore a previous session (key + delegation chain) from
  // storage. If found and still valid, sets #identity and #chain so the
  // client is ready to use without a new signIn().
  async #hydrate(): Promise<void> {
    const restored = await this.#restoreSession();
    const key = restored?.identity;
    const chain = restored?.chain;
    if (!key || !chain) {
      // Nothing to restore, so this origin cannot act — and saying otherwise is
      // what the state leading forbids. Discarded rather than removed, because a
      // record that reaches past this origin belongs to whoever published it.
      if (this.#stateStorage.get(this.#slots.state)?.held) await this.#dropSession();
      this.#installIdentity(new AnonymousIdentity());
      return;
    }

    // The state decides whether this origin is signed in, so a chain it does not
    // back belongs to a sign-in that has ended: drop it rather than restore it,
    // or getIdentity() would hand back an identity isAuthenticated() calls
    // signed out. Asked after the chain is read, so a visitor who was never
    // signed in removes nothing.
    if (this.#stateStorage.get(this.#slots.state) === null) {
      await this.#endSession();
      return;
    }

    if (!('sign' in key)) {
      this.#installIdentity(new AnonymousIdentity());
      return;
    }

    let identity: SessionIdentity;
    try {
      identity = await this.#openSession(key, chain);
    } catch (error) {
      // The record names an account this session cannot produce a credential
      // for, so it is not a sign-in this origin can act on. Dropped rather than
      // ended: on a shared store the record belongs to whoever published it,
      // and only the identity provider can say it is stale.
      if (!(error instanceof AccountMismatchError)) throw error;
      await this.#dropSession();
      this.#installIdentity(new AnonymousIdentity());
      return;
    }

    if (this.#disposed) {
      // Disposed while this was in flight: install nothing, and stop the refresh
      // this identity has already scheduled for itself.
      identity.dispose();
      return;
    }

    // The state decides who is signed in here, and a sibling subdomain can have
    // changed it while this origin was away. Credentials rooted at an account the
    // state no longer names belong to a sign-in that has ended, so they go rather
    // than being restored — the app credential with them, since `#openSession`
    // may have minted one for an account the state no longer names.
    const state = this.#stateStorage.get(this.#slots.state);
    if (state === null || state.principal.toText() !== identity.getPrincipal().toText()) {
      // Both of them: the one just opened, which was never installed, and
      // whatever this client was still answering with.
      identity.dispose();
      this.#installIdentity(new AnonymousIdentity());
      await this.#dropSession();
      return;
    }
    this.#installIdentity(identity);
  }

  /**
   * Stores the session as one record and records the state it puts this origin
   * in, so {@link isAuthenticated} can answer without reading it back.
   */
  async #persistSession(
    identity: SignIdentity,
    chain: DelegationChain,
    accountKey: DerEncodedPublicKey,
  ): Promise<void> {
    await this.#credentialStorage.set(this.#slots.session, { identity, chain });

    let earliest: bigint | null = null;
    for (const { delegation } of chain.delegations) {
      if (earliest === null || delegation.expiration < earliest) {
        earliest = delegation.expiration;
      }
    }
    if (earliest !== null) {
      // The account is what a mint reported, and the sign-in lasts as long as
      // the session chain's earliest delegation.
      this.#stateStorage.set(this.#slots.state, {
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
    this.#stateStorage.remove(this.#slots.state);
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
    this.#stateStorage.discard(this.#slots.state);
    await this.#clearCredentials();
  }

  // Every slot a completed sign-in writes. Not the ceremony's pending slot: a
  // flow that completed has already emptied it, and one that has not may still
  // return for it — a sign-out here cannot tell an abandoned key from a live one.
  //
  // The state is retracted before this by both callers: it is what says whether
  // this origin is signed in, and a teardown that failed partway must not leave
  // it saying yes.
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
  ssoDomain?: never;
  keys?: readonly K[];
}): `openid:${(typeof OPENID_PROVIDER_URLS)[P]}:${K}`[];
/**
 * Scopes attribute keys to an organization's SSO.
 *
 * When using one-click SSO sign-in, attributes can be scoped to the same
 * organization so the user grants access in a single step.
 *
 * @param params.ssoDomain - The organization domain the keys should be scoped to.
 * @param params.keys - The attribute keys to scope. Defaults to `['name', 'email']`;
 *   `verified_email` is not available for an organization SSO.
 * @returns The scoped attribute keys as `sso:<domain>:<key>`.
 *
 * @example
 * scopedKeys({ ssoDomain: 'dfinity.org', keys: ['email'] });
 * // ['sso:dfinity.org:email']
 */
export function scopedKeys<
  D extends string,
  K extends string = (typeof DEFAULT_SSO_SCOPE_KEYS)[number],
>(params: {
  ssoDomain: D;
  openIdProvider?: never;
  keys?: readonly K[];
}): `sso:${Lowercase<D>}:${K}`[];
export function scopedKeys(params: {
  openIdProvider?: OpenIdProvider;
  ssoDomain?: string;
  keys?: readonly string[];
}): string[] {
  if (params.openIdProvider !== undefined && params.ssoDomain !== undefined) {
    throw new Error('openIdProvider and ssoDomain are mutually exclusive');
  }
  if (params.ssoDomain !== undefined) {
    const domain = normalizeSsoDomain(params.ssoDomain);
    const keys = params.keys ?? DEFAULT_SSO_SCOPE_KEYS;
    return keys.map((key) => `sso:${domain}:${key}`);
  }
  if (params.openIdProvider === undefined) {
    throw new Error('scopedKeys requires either openIdProvider or ssoDomain');
  }
  const provider = OPENID_PROVIDER_URLS[params.openIdProvider];
  const keys = params.keys ?? DEFAULT_OPENID_SCOPE_KEYS;
  return keys.map((key) => `openid:${provider}:${key}`);
}
