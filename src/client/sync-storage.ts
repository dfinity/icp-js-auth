import { isLoopbackHost } from '../shared-session/protocol.js';

/**
 * Synchronous storage for non-secret values.
 *
 * {@link AuthClient.isAuthenticated} answers without awaiting, so what it reads
 * cannot come from the session store: that one is asynchronous, and with a
 * shared session it belongs to another origin. Only values that may be read and
 * written by any script on the domain belong here.
 */
export interface AuthClientSyncStorage {
  get(key: string): string | null;

  /**
   * @param key - Name to store the value under.
   * @param value - The value to store.
   * @param expiresAt - When the value stops being true, in milliseconds since
   * the epoch. Backends that can expire a value drop it then; others ignore it.
   */
  set(key: string, value: string, expiresAt?: number): void;

  remove(key: string): void;
}

/**
 * Default synchronous storage, scoped to the current origin.
 * @see implements {@link AuthClientSyncStorage}
 */
export class SyncLocalStorage implements AuthClientSyncStorage {
  get(key: string): string | null {
    return localStorage.getItem(key);
  }

  // Declared but ignored: localStorage cannot expire a value, and dropping the
  // parameter would make this class unusable where the interface is expected.
  // The value it holds is a timestamp the reader compares against the current
  // time anyway.
  set(key: string, value: string, _expiresAt?: number): void {
    localStorage.setItem(key, value);
  }

  remove(key: string): void {
    localStorage.removeItem(key);
  }
}

export interface SyncCookieStorageOptions {
  /**
   * Domain to scope the cookie to, e.g. `example.com` to reach it from
   * `a.example.com` and `b.example.com`.
   *
   * Must be the current host or a domain above it: a browser rejects a cookie
   * scoped to anything else, including a sibling subdomain. It also refuses a
   * public suffix, so an over-broad value fails rather than leaking to
   * unrelated sites. Nothing needs to be served at the domain — it is only a
   * storage and matching key.
   */
  domain: string;

  /**
   * Derivation origin of the session this store describes.
   *
   * It is part of the cookie's name, so two shared sessions below one domain —
   * a staging deployment beside production — do not write the same cookie and
   * describe each other's state. Pass the same value given to the session's
   * storage and to {@link AuthClient}.
   */
  derivationOrigin: string | URL;
}

/**
 * Synchronous storage shared by a domain and its subdomains.
 *
 * A cookie is the only store that is both synchronous and visible across
 * origins, which is what {@link AuthClient.isAuthenticated} needs when the
 * session itself lives on another origin.
 *
 * It is readable and writable by every subdomain, and unlike `localStorage` it
 * is not origin-scoped: any of them can overwrite it, and nothing records which
 * one did. Store only values whose authority rests elsewhere.
 * @see implements {@link AuthClientSyncStorage}
 */
export class SyncCookieStorage implements AuthClientSyncStorage {
  readonly #attributes: string;
  readonly #suffix: string;

  constructor(options: SyncCookieStorageOptions) {
    this.#suffix = `.${toCookieName(options.derivationOrigin.toString())}`;
    this.#attributes = [
      // Host-only on loopback: browsers reject `Domain=localhost`, and a
      // host-only cookie is already shared across ports, which is what a local
      // multi-origin setup needs.
      ...(isLoopbackHost(options.domain) ? [] : [`Domain=${options.domain}`]),
      'Path=/',
      'SameSite=Lax',
      // Loopback is a secure context, but Safari rejects Secure over http.
      ...(location.protocol === 'https:' ? ['Secure'] : []),
    ].join('; ');
  }

  get(key: string): string | null {
    const name = this.#nameFor(key);
    for (const entry of document.cookie.split(';')) {
      const separator = entry.indexOf('=');
      if (separator === -1) continue;
      if (decodeURIComponent(entry.slice(0, separator).trim()) !== name) continue;
      return decodeURIComponent(entry.slice(separator + 1).trim());
    }
    return null;
  }

  set(key: string, value: string, expiresAt?: number): void {
    const cookie = [
      `${encodeURIComponent(this.#nameFor(key))}=${encodeURIComponent(value)}`,
      this.#attributes,
    ];
    if (expiresAt !== undefined) {
      const seconds = Math.floor((expiresAt - Date.now()) / 1000);
      // Already elapsed: writing it would store a value that is untrue on the
      // very next read.
      if (seconds <= 0) {
        this.remove(key);
        return;
      }
      // The cookie expires with the value it describes, so there is no state in
      // which it outlives what it is a hint about.
      cookie.push(`Max-Age=${seconds}`);
    }
    // biome-ignore lint/suspicious/noDocumentCookie: the Cookie Store API is asynchronous, and this store exists to be read synchronously.
    document.cookie = cookie.join('; ');
  }

  remove(key: string): void {
    // biome-ignore lint/suspicious/noDocumentCookie: the Cookie Store API is asynchronous, and this store exists to be read synchronously.
    document.cookie = `${encodeURIComponent(this.#nameFor(key))}=; ${this.#attributes}; Max-Age=0`;
  }

  #nameFor(key: string): string {
    return `${key}${this.#suffix}`;
  }
}

// A cookie name is an RFC 6265 token, so characters an origin may contain — the
// colon before a port, slashes — are not allowed in one.
const NON_TOKEN = /[^!#$%&'*+\-.0-9A-Z^_`a-z|~]/g;

function toCookieName(value: string): string {
  let normalized = value;
  try {
    // Reduced to an origin so that a derivation origin written with a trailing
    // slash or a path does not name a second cookie.
    normalized = new URL(value).origin;
  } catch {
    // Not a URL; used as given.
  }
  return normalized.replace(NON_TOKEN, '_');
}
