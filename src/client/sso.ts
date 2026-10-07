// The identity provider's cap on the domain it will fetch.
const MAX_AUTHORITY_LENGTH = 255;

/**
 * `localhost` / `127.0.0.1`, optionally followed by `:<port>`. IPv6 loopback
 * (`[::1]`, etc.) is intentionally not handled — the identity provider doesn't
 * recognise it either, and its e2e setup uses the hostname form.
 */
function isLoopbackHost(host: string): boolean {
  let url: URL;
  try {
    // Parse as a URL authority so the optional `:<port>` is split off for us
    // rather than by hand. Invalid input throws and is treated as non-loopback.
    url = new URL(`http://${host}`);
  } catch {
    return false;
  }
  // A bare `host[:port]` has no path/query/fragment; reject e.g. `localhost/x`.
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') {
    return false;
  }
  return url.hostname === 'localhost' || url.hostname === '127.0.0.1';
}

/**
 * Normalizes an SSO domain to the authority the identity provider fetches the
 * discovery document from: lowercased and IDNA-encoded. A loopback host may
 * carry a port, for a local mock provider; any other host may not.
 *
 * @param domain - The organization domain.
 * @returns The normalized authority.
 * @throws When `domain` is not a domain.
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
    throw new Error(`ssoDomain must be a domain and nothing else: ${trimmed}`);
  }
  if (url.port !== '' && !isLoopbackHost(authority)) {
    throw new Error(`ssoDomain must be a domain and nothing else: ${trimmed}`);
  }
  if (authority.length > MAX_AUTHORITY_LENGTH) {
    throw new Error(`ssoDomain exceeds ${MAX_AUTHORITY_LENGTH} characters`);
  }
  // A bare hostname is a half-typed domain, not something worth a request.
  if (!authority.includes('.') && !isLoopbackHost(authority)) {
    throw new Error(`ssoDomain is not a domain name: ${trimmed}`);
  }
  return authority;
}
