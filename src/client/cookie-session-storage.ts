import { Principal } from '@icp-sdk/core/principal';
import { LocalSessionStorage } from './local-session-storage.js';
import type { Session, SessionStorage } from './session-storage.js';

// Default storage slot for the session and the name of the hint cookie.
// Owned by this implementation; override per instance via the options.
const DEFAULT_KEY = 'ic-delegation';

/** Whether a hostname is loopback, which browsers treat as a secure context. */
const isLoopbackHost = (hostname: string): boolean =>
  hostname === 'localhost' ||
  hostname.endsWith('.localhost') ||
  hostname === '127.0.0.1' ||
  hostname === '[::1]';

export interface CookieSessionStorageOptions {
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

  /**
   * Storage key for the delegation in `localStorage` and the name of the hint
   * cookie. Only one shared session per domain, so change this only to avoid a
   * collision with another cookie under the same domain.
   * @default 'ic-delegation'
   */
  key?: string;
}

/** A cross-subdomain sign-in hint: which principal is signed in, and until when. */
export interface SessionHint {
  principal: Principal;
  /** Delegation expiry, in milliseconds since the epoch. */
  expiresAtMs: number;
}

/**
 * Session storage that also announces sign-in state across sibling subdomains.
 *
 * The session itself stays in `localStorage` — per origin, and too large for a
 * cookie — so this composes {@link LocalSessionStorage} for it and layers a
 * cross-subdomain **hint cookie** on top: the principal and
 * the delegation's expiry, enough for a sibling subdomain to know a session
 * exists and for whom, and to notice a sign-out. Each subdomain re-issues its
 * own chain via a `prompt: 'none'` request; the cookie carries no key material
 * and no chain.
 *
 * The hint is derived from the delegation on {@link set}, so the caller stores
 * only the chain and the cookie follows automatically. {@link subscribe} fires
 * on both a same-origin `storage` change (another tab) and a hint-cookie change
 * (another subdomain).
 * @see implements {@link SessionStorage}
 */
export class CookieSessionStorage implements SessionStorage {
  readonly #local: LocalSessionStorage;
  readonly #attributes: string;
  // Per-subscriber checks, invoked on a same-tab write, a `storage` event, or a
  // cookie change.
  #subscribers = new Set<() => void>();

  /** Storage key for the delegation and the name of the hint cookie. */
  public readonly key: string;

  constructor(options: CookieSessionStorageOptions) {
    this.key = options.key ?? DEFAULT_KEY;
    this.#local = new LocalSessionStorage(this.key);
    const loopback = isLoopbackHost(options.domain);

    // A browser silently ignores `document.cookie` when the domain is not this
    // host or one above it, and the hint cookie is what makes a stored session
    // count as live, so the session would appear to be forgotten the moment it
    // was written. Refusing here names the cause; the silent version does not.
    const hostname = globalThis.location?.hostname;
    if (
      !loopback &&
      hostname !== undefined &&
      hostname !== options.domain &&
      !hostname.endsWith(`.${options.domain}`)
    ) {
      throw new Error(
        `A cookie cannot be scoped to '${options.domain}' from '${hostname}': the domain has to be this host or one above it`,
      );
    }

    const secure = globalThis.location?.protocol === 'https:';
    this.#attributes = [
      // Host-only on loopback: browsers reject `Domain=localhost`, and a
      // host-only cookie already spans ports, which local multi-origin needs.
      ...(loopback ? [] : [`Domain=${options.domain}`]),
      'Path=/',
      'SameSite=Lax',
      // Loopback is a secure context, but a `Secure` cookie over http is not
      // reliably accepted.
      ...(secure ? ['Secure'] : []),
    ].join('; ');
  }

  // The session lives in localStorage (per origin), but the shared hint cookie
  // is authoritative for whether it is still alive: if a sibling subdomain
  // signed out (cookie gone) or switched identity (cookie names another
  // principal), this origin's session is stale. Gate on the cookie and drop a
  // stale session, so a cross-subdomain sign-out surfaces through the plain
  // `get` / `isAuthenticated` path with no special-casing in the client.
  public get(): Session | null {
    const session = this.#local.get();
    if (session === null) return null;

    const cookieHint = this.readHint();
    const localHint = deriveHint(session);
    if (
      cookieHint === null ||
      localHint === null ||
      cookieHint.principal.toText() !== localHint.principal.toText()
    ) {
      this.#local.remove();
      return null;
    }
    return session;
  }

  public set(session: Session): void {
    this.#local.set(session);

    const hint = deriveHint(session);
    const seconds = hint === null ? 0 : Math.floor((hint.expiresAtMs - Date.now()) / 1000);
    if (hint === null || seconds <= 0) {
      this.#removeCookie();
    } else {
      const payload = `${hint.principal.toText()}|${hint.expiresAtMs}`;
      // biome-ignore lint/suspicious/noDocumentCookie: the Cookie Store API is async; this hint is written and read synchronously alongside isAuthenticated().
      document.cookie = `${encodeURIComponent(this.key)}=${encodeURIComponent(payload)}; ${this.#attributes}; Max-Age=${seconds}`;
    }
    // Notify after both localStorage and the cookie are written, so subscribers
    // observe a consistent snapshot.
    this.#fire();
  }

  public remove(): void {
    this.#local.remove();
    this.#removeCookie();
    this.#fire();
  }

  /**
   * The cross-subdomain hint, or `null` when no session is announced.
   *
   * An app reads this on load to decide whether to acquire a session silently
   * (`prompt: 'none'` with `hint`) when this origin has no local delegation yet.
   */
  public readHint(): SessionHint | null {
    const raw = readCookie(this.key);
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

  public subscribe(listener: () => void): () => void {
    // A single logical change can reach this client from several sources at
    // once — a same-tab write calls #fire, a cross-tab write is a `storage`
    // event, and a sibling subdomain's cookie change shows up through the cookie
    // watchers. Route every source through one `check` that fires the listener
    // only when the observed state (delegation + cookie) actually changed since
    // the last fire, so the listener is called once per change, not per source.
    let last = this.#snapshot();
    const check = (): void => {
      const snapshot = this.#snapshot();
      if (snapshot !== last) {
        last = snapshot;
        listener();
      }
    };
    // Registered so same-tab set/remove reach this subscriber via #fire.
    this.#subscribers.add(check);

    // Cross-tab writes to the delegation arrive as a `storage` event.
    const onStorage = (event: StorageEvent): void => {
      if (event.storageArea !== localStorage) return;
      if (event.key === this.key || event.key === null) check();
    };
    globalThis.addEventListener('storage', onStorage);

    // The hint cookie changes when another subdomain signs in or out.
    // `document.cookie` fires no event, so watch it: the Cookie Store API where
    // present, and a re-check whenever the tab is shown or the window regains
    // focus, which covers browsers without it. `focus` catches the case
    // `visibilitychange` misses — two visible windows side by side, where moving
    // focus between them is not a visibility change.
    const onVisible = (): void => {
      if (document.visibilityState === 'visible') check();
    };
    document.addEventListener('visibilitychange', onVisible);
    globalThis.addEventListener('pageshow', check);
    globalThis.addEventListener('focus', check);

    const cookieStore = (globalThis as { cookieStore?: EventTarget }).cookieStore;
    cookieStore?.addEventListener('change', check);

    return () => {
      this.#subscribers.delete(check);
      globalThis.removeEventListener('storage', onStorage);
      document.removeEventListener('visibilitychange', onVisible);
      globalThis.removeEventListener('pageshow', check);
      globalThis.removeEventListener('focus', check);
      cookieStore?.removeEventListener('change', check);
    };
  }

  #fire(): void {
    for (const check of this.#subscribers) check();
  }

  // A snapshot of everything a listener observes: the stored delegation and the
  // hint cookie. Two triggers for the same change produce the same snapshot, so
  // comparing against the last one collapses them into a single notification.
  #snapshot(): string {
    return `${localStorage.getItem(this.key) ?? ''}|${readCookie(this.key) ?? ''}`;
  }

  #removeCookie(): void {
    // biome-ignore lint/suspicious/noDocumentCookie: same reason as set().
    document.cookie = `${encodeURIComponent(this.key)}=; ${this.#attributes}; Max-Age=0`;
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
 * Derives the hint (principal + earliest expiry) from a session, or `null` if its
 * chain has no delegations. The principal is the self-authenticating id of the
 * chain's public key; the expiry is the chain's earliest delegation expiry, since
 * that is when the session stops being usable.
 */
function deriveHint({ chain }: Session): SessionHint | null {
  const expirations = chain.delegations.map(({ delegation }) => delegation.expiration);
  if (expirations.length === 0) return null;
  const earliestNs = expirations.reduce((a, b) => (a < b ? a : b));
  return {
    principal: Principal.selfAuthenticating(new Uint8Array(chain.publicKey)),
    expiresAtMs: Number(earliestNs / 1_000_000n),
  };
}
