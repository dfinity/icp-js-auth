/**
 * Organization SSO domains: the format the identity provider accepts, and a
 * check that a domain actually publishes an SSO configuration.
 */

const MAX_DOMAIN_LENGTH = 253;
const MAX_LABEL_LENGTH = 63;
// Dot-separated DNS labels of alphanumerics, hyphens allowed only inside a
// label. Applied to the lowercased domain, so no uppercase range is needed.
const DOMAIN_REGEX = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

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
 * `localhost` / `127.0.0.1`, optionally with a port. Loopback hosts serve the
 * configuration over plain `http` and are not DNS names, so they take a
 * different scheme and skip the DNS-format check.
 */
function isLoopbackHost(domain: string): boolean {
  let url: URL;
  try {
    // Parsed as a URL authority so an optional `:<port>` is split off for us.
    url = new URL(`http://${domain}`);
  } catch {
    return false;
  }
  // A bare `host[:port]` carries nothing else; reject e.g. `localhost/x`.
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') {
    return false;
  }
  return url.hostname === 'localhost' || url.hostname === '127.0.0.1';
}

/**
 * Trims and lowercases an SSO domain, and checks it is a bare DNS name — a
 * host, optionally `host:port`, and nothing else. The identity provider takes
 * the domain as the authority of the discovery URL it fetches, so a value
 * carrying a scheme, path, query, or fragment cannot resolve.
 *
 * @param domain - The organization domain.
 * @returns The normalized domain.
 * @throws When `domain` is not a bare DNS name.
 */
export function normalizeSsoDomain(domain: string): string {
  const normalized = domain.trim().toLowerCase();
  if (normalized.length === 0) {
    throw new Error('ssoDomain cannot be empty');
  }
  if (normalized.length > MAX_DOMAIN_LENGTH) {
    throw new Error(`ssoDomain exceeds ${MAX_DOMAIN_LENGTH} characters`);
  }
  if (isLoopbackHost(normalized)) {
    return normalized;
  }
  if (!DOMAIN_REGEX.test(normalized)) {
    throw new Error(`ssoDomain is not a domain name: ${normalized}`);
  }
  const labels = normalized.split('.');
  if (labels.length < 2) {
    throw new Error(`ssoDomain must have at least two labels: ${normalized}`);
  }
  if (labels.some((label) => label.length > MAX_LABEL_LENGTH)) {
    throw new Error(`ssoDomain has a label over ${MAX_LABEL_LENGTH} characters`);
  }
  return normalized;
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

  const scheme = isLoopbackHost(normalized) ? 'http' : 'https';
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
