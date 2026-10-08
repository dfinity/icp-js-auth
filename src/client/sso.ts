// The identity provider's cap on the domain it will fetch.
const MAX_AUTHORITY_LENGTH = 255;

// The identity provider's own limits on a DNS name (idna's strict mode).
const MAX_DNS_NAME_LENGTH = 253;

// 1 to 63 letters, digits, or hyphens, with no hyphen at either end.
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function isDnsName(host: string): boolean {
  const labels = host.split('.');
  return (
    host.length <= MAX_DNS_NAME_LENGTH &&
    labels.length >= 2 &&
    labels.every(
      (label) =>
        DNS_LABEL.test(label) &&
        // `--` in the third and fourth places is reserved, except for punycode.
        (label.slice(2, 4) !== '--' || label.startsWith('xn--')),
    )
  );
}

const MAX_QUOTED_LENGTH = 100;

/** `value` for an error message: cut short, and quoted so control characters show escaped. */
function quote(value: string): string {
  return JSON.stringify(
    value.length > MAX_QUOTED_LENGTH ? `${value.slice(0, MAX_QUOTED_LENGTH)}…` : value,
  );
}

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
    throw new Error(`ssoDomain ${quote(trimmed)} is not a domain`);
  }
  const authority = url.host;
  // Rebuilding from the host and port alone has to reproduce what was parsed,
  // so anything else the domain carried shows up as a difference.
  if (new URL(`https://${authority}`).href !== url.href) {
    throw new Error(
      `ssoDomain ${quote(trimmed)} must be a domain and nothing else: no scheme, path, query, fragment, or userinfo`,
    );
  }
  // `URL` drops an empty or default port such as `:443`, so look at the input itself.
  const port = /:([0-9]*)$/.exec(trimmed)?.[1];
  if (port !== undefined && (port === '' || port !== url.port || !isLoopbackHost(authority))) {
    throw new Error(
      `ssoDomain ${quote(trimmed)} has a port, which only localhost and 127.0.0.1 may carry`,
    );
  }
  if (isLoopbackHost(authority)) {
    return authority;
  }
  if (authority.length > MAX_AUTHORITY_LENGTH) {
    throw new Error(`ssoDomain ${quote(trimmed)} exceeds ${MAX_AUTHORITY_LENGTH} characters`);
  }
  if (!isDnsName(authority)) {
    throw new Error(
      `ssoDomain ${quote(trimmed)} is not a domain name: it needs at least two labels of 1 to 63 letters, digits, or hyphens, with no hyphen at either end and no "--" in the third and fourth places, and at most ${MAX_DNS_NAME_LENGTH} characters`,
    );
  }
  return authority;
}
