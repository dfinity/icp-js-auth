import { DelegationChain } from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';

/**
 * Synchronous storage for the delegation chain.
 *
 * The chain is not secret — it travels in the clear in every call envelope — so
 * unlike the key pair (which stays in the async {@link AuthClientStorage}) it can
 * live in a store that is synchronous and, crucially, observable across tabs and
 * origins. That is what lets {@link AuthClient.isAuthenticated} answer without an
 * async read, and what lets one tab or sibling origin react to a sign-in or
 * sign-out in another.
 *
 * The key pair never comes here: a `CryptoKey` cannot be serialized to a string
 * store, and keeping it out is what preserves its non-extractability.
 */
export interface AuthClientSyncStorage {
  /** The stored value for `key`, or `null` if absent. */
  get(key: string): string | null;

  /** Stores `value` under `key`, replacing any previous value. */
  set(key: string, value: string): void;

  /** Removes `key`. */
  remove(key: string): void;

  /**
   * Subscribes to changes to `key` made outside this client — another tab on
   * the same origin, or another subdomain sharing the store. Fires after the
   * change is visible to {@link get}. Returns a function that unsubscribes.
   *
   * The change made by this client's own {@link set} / {@link remove} does not
   * fire the listener; only changes originating elsewhere do.
   */
  subscribe(key: string, listener: () => void): () => void;
}

/**
 * Default synchronous storage: `localStorage`, scoped to the current origin.
 *
 * Cross-tab aware — the browser's `storage` event fires in the *other* tabs of
 * the same origin when the delegation is written or removed, so a sign-in or
 * sign-out in one tab reaches the rest. Not cross-origin: for a session shared
 * across sibling subdomains, use {@link SyncCookieStorage}.
 * @see implements {@link AuthClientSyncStorage}
 */
export class SyncLocalStorage implements AuthClientSyncStorage {
  get(key: string): string | null {
    return localStorage.getItem(key);
  }

  set(key: string, value: string): void {
    localStorage.setItem(key, value);
  }

  remove(key: string): void {
    localStorage.removeItem(key);
  }

  subscribe(key: string, listener: () => void): () => void {
    const handler = (event: StorageEvent): void => {
      // `key === null` is a wholesale `localStorage.clear()`, which also drops
      // our value, so treat it as a change too.
      if (event.storageArea === localStorage && (event.key === key || event.key === null)) {
        listener();
      }
    };
    window.addEventListener('storage', handler);
    return () => window.removeEventListener('storage', handler);
  }
}

/** Whether a hostname is loopback, which browsers treat as a secure context. */
const isLoopbackHost = (hostname: string): boolean =>
  hostname === 'localhost' ||
  hostname.endsWith('.localhost') ||
  hostname === '127.0.0.1' ||
  hostname === '[::1]';

export interface SyncCookieStorageOptions {
  /**
   * Domain to scope the hint cookie to, e.g. `example.com` so `a.example.com`
   * and `b.example.com` can see each other's sign-in state.
   *
   * Must be the current host or a domain above it: the browser rejects a cookie
   * scoped to anything else, including a sibling subdomain, and refuses a public
   * suffix — so an over-broad value fails rather than leaking to unrelated
   * sites. Nothing needs to be served at the domain; it is only a scope.
   */
  domain: string;
}

/** A cross-subdomain sign-in hint: which principal is signed in, and until when. */
export interface SessionHint {
  principal: Principal;
  /** Delegation expiry, in milliseconds since the epoch. */
  expiresAtMs: number;
}

/**
 * Synchronous storage that also announces sign-in state across sibling
 * subdomains.
 *
 * The delegation chain itself stays in `localStorage` (per origin, and too large
 * for a cookie) — each subdomain re-issues its own via a `prompt: 'none'`
 * request. What crosses subdomains is a small **hint cookie**: the principal and
 * the delegation's expiry, enough for a sibling to know a session exists and for
 * whom, and to notice a sign-out. It carries no key material and no chain.
 *
 * The hint is derived from the delegation on {@link set}, so the caller stores
 * only the chain and the cookie follows automatically. `subscribe` fires on both
 * a same-origin `storage` change (another tab) and a hint-cookie change (another
 * subdomain).
 *
 * One shared session per domain: the cookie's name is the key it is given, so
 * two sessions below the same domain would describe each other's state.
 * @see implements {@link AuthClientSyncStorage}
 */
export class SyncCookieStorage implements AuthClientSyncStorage {
  readonly #attributes: string;
  readonly #secure: boolean;

  constructor(options: SyncCookieStorageOptions) {
    const loopback = isLoopbackHost(options.domain);
    this.#secure = globalThis.location?.protocol === 'https:';
    this.#attributes = [
      // Host-only on loopback: browsers reject `Domain=localhost`, and a
      // host-only cookie already spans ports, which local multi-origin needs.
      ...(loopback ? [] : [`Domain=${options.domain}`]),
      'Path=/',
      'SameSite=Lax',
      // Loopback is a secure context, but a `Secure` cookie over http is not
      // reliably accepted.
      ...(this.#secure ? ['Secure'] : []),
    ].join('; ');
  }

  // The chain lives in localStorage (per origin), but the shared hint cookie is
  // authoritative for whether the session is still alive: if a sibling subdomain
  // signed out (cookie gone) or switched identity (cookie names another
  // principal), this origin's chain is stale. Gate on the cookie and drop a
  // stale chain, so a cross-subdomain sign-out surfaces through the plain
  // `get` / `isAuthenticated` path with no special-casing in the client.
  get(key: string): string | null {
    const local = localStorage.getItem(key);
    if (local === null) return null;
    const hint = this.readHint(key);
    const localHint = deriveHint(local);
    if (
      hint === null ||
      localHint === null ||
      hint.principal.toText() !== localHint.principal.toText()
    ) {
      localStorage.removeItem(key);
      return null;
    }
    return local;
  }

  set(key: string, value: string): void {
    localStorage.setItem(key, value);
    const hint = deriveHint(value);
    if (hint === null) {
      this.#removeCookie(key);
      return;
    }
    const seconds = Math.floor((hint.expiresAtMs - Date.now()) / 1000);
    if (seconds <= 0) {
      this.#removeCookie(key);
      return;
    }
    const payload = `${hint.principal.toText()}|${hint.expiresAtMs}`;
    // biome-ignore lint/suspicious/noDocumentCookie: the Cookie Store API is async; this hint is written and read synchronously alongside isAuthenticated().
    document.cookie = `${encodeURIComponent(key)}=${encodeURIComponent(payload)}; ${this.#attributes}; Max-Age=${seconds}`;
  }

  remove(key: string): void {
    localStorage.removeItem(key);
    this.#removeCookie(key);
  }

  /**
   * The cross-subdomain hint for `key`, or `null` when no session is announced.
   *
   * An app reads this on load to decide whether to acquire a session silently
   * (`prompt: 'none'` with `hint`) when this origin has no local delegation yet.
   */
  readHint(key: string): SessionHint | null {
    const raw = readCookie(key);
    if (raw === null) return null;
    const [principalText, expiresAt] = raw.split('|');
    const expiresAtMs = Number(expiresAt);
    if (principalText === undefined || !Number.isFinite(expiresAtMs)) return null;
    try {
      return { principal: Principal.fromText(principalText), expiresAtMs };
    } catch {
      return null;
    }
  }

  subscribe(key: string, listener: () => void): () => void {
    const onStorage = (event: StorageEvent): void => {
      if (event.storageArea === localStorage && (event.key === key || event.key === null)) {
        listener();
      }
    };
    window.addEventListener('storage', onStorage);

    // The hint cookie changes when another subdomain signs in or out. `document.cookie`
    // fires no event, so watch it: the Cookie Store API where present, and a
    // re-check whenever the tab is shown again, which also covers browsers
    // without it.
    let lastHint = readCookie(key);
    const check = (): void => {
      const current = readCookie(key);
      if (current !== lastHint) {
        lastHint = current;
        listener();
      }
    };
    const onVisible = (): void => {
      if (document.visibilityState === 'visible') check();
    };
    document.addEventListener('visibilitychange', onVisible);
    window.addEventListener('pageshow', check);

    const cookieStore = (globalThis as { cookieStore?: EventTarget }).cookieStore;
    cookieStore?.addEventListener('change', check);

    return () => {
      window.removeEventListener('storage', onStorage);
      document.removeEventListener('visibilitychange', onVisible);
      window.removeEventListener('pageshow', check);
      cookieStore?.removeEventListener('change', check);
    };
  }

  #removeCookie(key: string): void {
    // biome-ignore lint/suspicious/noDocumentCookie: same reason as set().
    document.cookie = `${encodeURIComponent(key)}=; ${this.#attributes}; Max-Age=0`;
  }
}

/** Reads a cookie value by name, or `null` if absent. */
function readCookie(key: string): string | null {
  for (const entry of document.cookie.split(';')) {
    const separator = entry.indexOf('=');
    if (separator === -1) continue;
    if (decodeURIComponent(entry.slice(0, separator).trim()) !== key) continue;
    return decodeURIComponent(entry.slice(separator + 1).trim());
  }
  return null;
}

/**
 * Derives the hint (principal + earliest expiry) from a stored delegation chain,
 * or `null` if the value is not a chain this can read. The principal is the
 * self-authenticating id of the chain's public key; the expiry is the chain's
 * earliest delegation expiry, since that is when it stops being usable.
 */
function deriveHint(chainJson: string): SessionHint | null {
  try {
    const chain = DelegationChain.fromJSON(JSON.parse(chainJson));
    const expirations = chain.delegations.map(({ delegation }) => delegation.expiration);
    if (expirations.length === 0) return null;
    const earliestNs = expirations.reduce((a, b) => (a < b ? a : b));
    return {
      principal: Principal.selfAuthenticating(new Uint8Array(chain.publicKey)),
      expiresAtMs: Number(earliestNs / 1_000_000n),
    };
  } catch {
    return null;
  }
}
