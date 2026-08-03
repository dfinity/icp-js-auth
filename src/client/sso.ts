/**
 * Organization SSO domains: the format the identity provider accepts, and a
 * check that a domain actually publishes an SSO configuration.
 */

// Matches the identity provider's own cap on the domain it will fetch.
const MAX_AUTHORITY_LENGTH = 255;

const WELL_KNOWN_PATH = '/.well-known/ii-openid-configuration';

// Floor on how quickly the check can report `false`. A form that checks on key
// entry asks about a partially typed domain for as long as the user is typing,
// and every one of those is invalid; resolving at format-check speed turns that
// into an error flashing on each keystroke. Slower than any single keystroke,
// short enough to stay responsive once the user stops.
const MIN_DURATION_MS = 750;

/**
 * Resolves after `ms`, or rejects if `signal` aborts first — so an abandoned
 * check rejects on the spot instead of waiting out the floor.
 */
function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted === true) {
    return Promise.reject(signal.reason);
  }
  return new Promise((resolve, reject) => {
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * `localhost` / `127.0.0.1`, with or without a port. Loopback hosts serve the
 * configuration over plain `http` and carry no dot.
 */
function isLoopbackAuthority(authority: string): boolean {
  const host = authority.split(':')[0];
  return host === 'localhost' || host === '127.0.0.1';
}

/**
 * Normalizes an SSO domain to the authority the identity provider will fetch
 * the discovery document from: lowercased, IDNA-encoded, and carrying nothing
 * but a host and an optional port.
 *
 * The domain is parsed as that authority, so `URL` does the work — a value
 * carrying a scheme, userinfo, path, query, or fragment cannot be one, and an
 * internationalized domain becomes the punycode form the identity provider
 * resolves (`中国.cn` → `xn--fiqs8s.cn`).
 *
 * @param domain - The organization domain.
 * @returns The normalized authority.
 * @throws When `domain` is not a domain with an optional port.
 */
export function normalizeSsoDomain(domain: string): string {
  const trimmed = domain.trim();
  if (trimmed.length === 0) {
    throw new Error('ssoDomain cannot be empty');
  }
  let url: URL;
  try {
    url = new URL(`https://${trimmed}`);
  } catch {
    throw new Error(`ssoDomain is not a domain: ${trimmed}`);
  }
  if (
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== '' ||
    (url.pathname !== '' && url.pathname !== '/')
  ) {
    throw new Error(`ssoDomain must be a domain and optional port, nothing else: ${trimmed}`);
  }
  // `host` is the hostname plus a non-default port, which is the authority the
  // identity provider reconstructs from the same input.
  const authority = url.host;
  if (authority.length > MAX_AUTHORITY_LENGTH) {
    throw new Error(`ssoDomain exceeds ${MAX_AUTHORITY_LENGTH} characters`);
  }
  // An organization publishes its configuration under a domain name, so a bare
  // hostname is a half-typed domain rather than something worth a request.
  if (!authority.includes('.') && !isLoopbackAuthority(authority)) {
    throw new Error(`ssoDomain is not a domain name: ${trimmed}`);
  }
  return authority;
}

/** Shape of `/.well-known/ii-openid-configuration` this check requires. */
function publishesSsoConfiguration(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const { client_id, openid_configuration } = value as Record<string, unknown>;
  return typeof client_id === 'string' && typeof openid_configuration === 'string';
}

/**
 * Checks whether an organization domain can be used for SSO sign-in: it is a
 * well-formed domain name, and it publishes
 * `/.well-known/ii-openid-configuration` with a `client_id` and an
 * `openid_configuration` URL.
 *
 * The document must be served with `Access-Control-Allow-Origin: *` — it is a
 * public, unauthenticated configuration file, and a domain a browser cannot
 * read it from is not usable for SSO.
 *
 * Use it to validate a domain the user typed before handing it to
 * {@link AuthClient} as `ssoDomain`. It never resolves in under 750 ms, so
 * checking on key entry doesn't flash an error at every keystroke; abort the
 * previous check when the input changes, and debounce it too, since each call is
 * a request to a third-party server.
 *
 * @param domain - The organization domain.
 * @param signal - Aborts the in-flight check, e.g. when the input changes.
 * @returns Whether the domain is usable for SSO sign-in.
 * @throws When `signal` aborts — an abandoned check is not a verdict on the
 *   domain, so it must not be read as `false`.
 *
 * @example
 * if (await isValidSsoDomain(input.value)) {
 *   const authClient = new AuthClient({ ssoDomain: input.value });
 *   await authClient.signIn();
 * }
 */
export async function isValidSsoDomain(domain: string, signal?: AbortSignal): Promise<boolean> {
  const [valid] = await Promise.all([
    probeSsoDomain(domain, signal),
    sleep(MIN_DURATION_MS, signal),
  ]);
  return valid;
}

async function probeSsoDomain(domain: string, signal?: AbortSignal): Promise<boolean> {
  let normalized: string;
  try {
    normalized = normalizeSsoDomain(domain);
  } catch {
    return false;
  }

  const scheme = isLoopbackAuthority(normalized) ? 'http' : 'https';
  try {
    const response = await fetch(`${scheme}://${normalized}${WELL_KNOWN_PATH}`, {
      headers: { Accept: 'application/json' },
      signal,
    });
    if (!response.ok) {
      return false;
    }
    return publishesSsoConfiguration(await response.json());
  } catch (error) {
    if (signal?.aborted === true) {
      throw error;
    }
    // A DNS, TLS, CORS, or parse failure all leave the domain unusable for
    // sign-in, and a browser cannot tell them apart anyway.
    return false;
  }
}
