// The identity provider's cap on the domain it will fetch.
const MAX_AUTHORITY_LENGTH = 255;

const WELL_KNOWN_PATH = '/.well-known/ii-openid-configuration';

// Slower than a keystroke, so a form checking on key entry doesn't flash an
// error over every partially typed domain.
const MIN_DURATION_MS = 750;

/** Resolves after `ms`, or rejects if `signal` aborts first. */
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

function isLoopbackAuthority(authority: string): boolean {
  const host = authority.split(':')[0];
  return host === 'localhost' || host === '127.0.0.1';
}

/**
 * Normalizes an SSO domain to the authority the identity provider fetches the
 * discovery document from: lowercased, IDNA-encoded, host and optional port.
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
  const authority = url.host;
  // Rebuilding from the host and port alone has to reproduce what was parsed,
  // so anything else the domain carried shows up as a difference.
  if (new URL(`https://${authority}`).href !== url.href) {
    throw new Error(`ssoDomain must be a domain and optional port, nothing else: ${trimmed}`);
  }
  if (authority.length > MAX_AUTHORITY_LENGTH) {
    throw new Error(`ssoDomain exceeds ${MAX_AUTHORITY_LENGTH} characters`);
  }
  // A bare hostname is a half-typed domain, not something worth a request.
  if (!authority.includes('.') && !isLoopbackAuthority(authority)) {
    throw new Error(`ssoDomain is not a domain name: ${trimmed}`);
  }
  return authority;
}

function publishesSsoConfiguration(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const { client_id, openid_configuration } = value as Record<string, unknown>;
  return typeof client_id === 'string' && typeof openid_configuration === 'string';
}

/**
 * Checks whether an organization domain can be used for SSO sign-in: it is a
 * domain name, and it publishes `/.well-known/ii-openid-configuration` with a
 * `client_id` and an `openid_configuration` URL.
 *
 * The document must be served with `Access-Control-Allow-Origin: *`.
 *
 * Intended for a domain input, so it never resolves in under 750 ms. Debounce
 * the input too: each call is a request to a third-party server.
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
    // A DNS, TLS, CORS, or parse failure all leave the domain unusable.
    return false;
  }
}
