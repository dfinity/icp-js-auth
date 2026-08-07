import type { AuthClientStorage, StoredKey } from '../client/storage.js';
import {
  CHANNEL,
  DEFAULT_TIMEOUT_MS,
  isChannelMessage,
  isSecureOrigin,
  PROTOCOL_VERSION,
  type SharedSessionOp,
  type SharedSessionReady,
  type SharedSessionRequest,
  type SharedSessionResponse,
} from './protocol.js';

/** Location of the page that calls `serveSharedSession`. */
export interface SharedSessionHubOptions {
  /**
   * Absolute URL of the hub page, e.g.
   * `https://auth.example.com/.well-known/icp-auth-storage.html`.
   *
   * Must be `https`, except on loopback for local development.
   */
  url: string | URL;

  /**
   * Time to wait for the hub to load and to answer each operation, in milliseconds.
   * @default 10000
   */
  timeout?: number;
}

export interface SharedSessionStorageOptions {
  /** Where the shared session is served from. */
  hub: SharedSessionHubOptions;

  /**
   * Derivation origin the shared session belongs to.
   *
   * The hub authorizes readers from this origin's
   * `/.well-known/ii-alternative-origins` record, and refuses a client whose
   * derivation origin differs from the one it was configured with.
   */
  derivationOrigin: string | URL;
}

/**
 * Keeps the session in a store hosted by another origin, so every origin
 * authorized by the derivation origin shares one sign-in.
 *
 * The store itself lives in the hub page's IndexedDB; this class only proxies
 * operations to it over `postMessage`. Nothing is written on the calling origin,
 * and no credential is ever attached to an HTTP request.
 *
 * @see {@link https://js.icp.build/auth/}
 * @example
 * ```ts
 * const authClient = new AuthClient({
 *   sharedSessionHub: { url: 'https://auth.example.com/hub.html' },
 *   derivationOrigin: 'https://auth.example.com',
 * });
 * ```
 */
export class SharedSessionStorage implements AuthClientStorage {
  readonly #hubUrl: URL;
  readonly #hubOrigin: string;
  readonly #derivationOrigin: string;
  readonly #timeout: number;
  #connection: Promise<Window> | null = null;
  #lastId = 0;

  constructor(options: SharedSessionStorageOptions) {
    this.#hubUrl = parseAbsoluteUrl(options.hub.url, 'hub.url');
    if (!isSecureOrigin(this.#hubUrl)) {
      throw new Error(
        `Shared session hub must be served over https (or loopback for local development), got "${this.#hubUrl.origin}".`,
      );
    }
    this.#hubOrigin = this.#hubUrl.origin;
    this.#derivationOrigin = parseAbsoluteUrl(options.derivationOrigin, 'derivationOrigin').origin;
    this.#timeout = options.hub.timeout ?? DEFAULT_TIMEOUT_MS;
  }

  async get(key: string): Promise<StoredKey | null> {
    return await this.#call('get', key);
  }

  async set(key: string, value: StoredKey): Promise<void> {
    await this.#call('set', key, value);
  }

  async remove(key: string): Promise<void> {
    await this.#call('remove', key);
  }

  async #call(op: SharedSessionOp, key: string, value?: StoredKey): Promise<StoredKey | null> {
    const hub = await this.#connect();
    const id = ++this.#lastId;
    const request: SharedSessionRequest = {
      v: PROTOCOL_VERSION,
      type: CHANNEL,
      id,
      op,
      key,
      value,
      derivationOrigin: this.#derivationOrigin,
    };

    return await new Promise<StoredKey | null>((resolve, reject) => {
      const settle = (finish: () => void) => {
        clearTimeout(timer);
        removeEventListener('message', onMessage);
        finish();
      };

      const onMessage = (event: MessageEvent) => {
        if (event.origin !== this.#hubOrigin || !isChannelMessage(event.data)) return;
        const data = event.data as Partial<SharedSessionResponse>;
        if (data.id !== id) return;
        settle(() => {
          if (data.error !== undefined) {
            reject(new Error(`Shared session hub refused ${op}: ${data.error}`));
            return;
          }
          resolve(data.result ?? null);
        });
      };

      const timer = setTimeout(() => {
        settle(() =>
          reject(
            new Error(
              `Shared session hub at ${this.#hubUrl.toString()} did not answer ${op} within ${this.#timeout}ms.`,
            ),
          ),
        );
      }, this.#timeout);

      addEventListener('message', onMessage);
      hub.postMessage(request, this.#hubOrigin);
    });
  }

  // Memoized, but a failure is not cached: a hub that was briefly unreachable
  // must not leave this client unable to reach it for the page's lifetime.
  #connect(): Promise<Window> {
    if (this.#connection === null) {
      const connection = this.#openHub();
      connection.catch(() => {
        if (this.#connection === connection) {
          this.#connection = null;
        }
      });
      this.#connection = connection;
    }
    return this.#connection;
  }

  async #openHub(): Promise<Window> {
    await bodyReady();

    const frame = document.createElement('iframe');
    frame.hidden = true;
    frame.setAttribute('aria-hidden', 'true');
    frame.setAttribute('tabindex', '-1');
    frame.title = 'Shared session';
    frame.src = this.#hubUrl.toString();

    const ready = new Promise<Window>((resolve, reject) => {
      const settle = (finish: () => void) => {
        clearTimeout(timer);
        removeEventListener('message', onMessage);
        finish();
      };

      const onMessage = (event: MessageEvent) => {
        // Checking the source as well as the origin: another frame on the hub's
        // origin must not be able to answer for this one.
        if (event.origin !== this.#hubOrigin || event.source !== frame.contentWindow) return;
        if (!isChannelMessage(event.data)) return;
        const data = event.data as Partial<SharedSessionReady>;
        if (data.ready !== true) return;

        settle(() => {
          if (data.v !== PROTOCOL_VERSION) {
            reject(
              new Error(
                `Shared session hub at ${this.#hubUrl.toString()} speaks protocol version ${String(data.v)}, this client speaks ${PROTOCOL_VERSION}. Align the @icp-sdk/auth version deployed on both origins.`,
              ),
            );
            return;
          }
          const target = frame.contentWindow;
          if (target === null) {
            reject(
              new Error(`Shared session hub at ${this.#hubUrl.toString()} closed while loading.`),
            );
            return;
          }
          resolve(target);
        });
      };

      // A missing hub page still fires `load` on the iframe, so there is nothing
      // to listen for other than the handshake itself: a wrong URL, a redirect,
      // or a page that never calls `serveSharedSession` all present as silence.
      const timer = setTimeout(() => {
        settle(() =>
          reject(
            new Error(
              `Shared session hub at ${this.#hubUrl.toString()} did not respond within ${this.#timeout}ms. Check that the page is deployed at that URL, is not redirected, and calls serveSharedSession().`,
            ),
          ),
        );
      }, this.#timeout);

      addEventListener('message', onMessage);
    });

    document.body.append(frame);
    try {
      return await ready;
    } catch (error) {
      // Nothing will ever answer through this frame, and #connect allows a
      // retry, so leaving it attached would accumulate one dead frame per
      // attempt.
      frame.remove();
      throw error;
    }
  }
}

function parseAbsoluteUrl(value: string | URL, label: string): URL {
  try {
    return new URL(value.toString());
  } catch {
    throw new Error(`Shared session ${label} must be an absolute URL, got "${value.toString()}".`);
  }
}

function bodyReady(): Promise<void> {
  if (document.body !== null) return Promise.resolve();
  return new Promise((resolve) => {
    document.addEventListener('DOMContentLoaded', () => resolve(), { once: true });
  });
}
