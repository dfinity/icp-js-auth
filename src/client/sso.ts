// The identity provider's cap on the domain it will fetch.
const MAX_AUTHORITY_LENGTH = 255;

// The identity provider's own limits on a DNS name (idna's strict mode).
const MAX_DNS_NAME_LENGTH = 253;
const MAX_DNS_LABEL_LENGTH = 63;

const MAX_QUOTED_LENGTH = 100;

/** `value` for an error message: cut short, and quoted so control characters show escaped. */
function quote(value: string): string {
  return JSON.stringify(
    value.length > MAX_QUOTED_LENGTH ? `${value.slice(0, MAX_QUOTED_LENGTH)}…` : value,
  );
}

/**
 * `localhost`, `127.0.0.1`, or a name under `.localhost` (RFC 6761 reserves the
 * whole domain for loopback), like the identity provider's own check. IPv6
 * loopback is not one, there either.
 */
function isLoopbackHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname.endsWith('.localhost');
}

/** What keeps `hostname` from being a DNS name, by the identity provider's rules. */
function dnsNameProblems(hostname: string): string[] {
  const labels = hostname.split('.');
  const problems: string[] = [];
  if (labels.length < 2) problems.push('a single label');
  if (labels.some((label) => label.length === 0)) problems.push('an empty label');
  if (labels.some((label) => label.length > MAX_DNS_LABEL_LENGTH)) {
    problems.push(`a label longer than ${MAX_DNS_LABEL_LENGTH} characters`);
  }
  if (labels.some((label) => /[^a-z0-9-]/.test(label))) {
    problems.push('a character other than a letter, digit, or hyphen');
  }
  if (labels.some((label) => label.startsWith('-') || label.endsWith('-'))) {
    problems.push('a label starting or ending with a hyphen');
  }
  // `--` in the third and fourth places is reserved, except for punycode.
  if (labels.some((label) => label.slice(2, 4) === '--' && !label.startsWith('xn--'))) {
    problems.push('a label with "--" in its third and fourth places');
  }
  if (hostname.length > MAX_DNS_NAME_LENGTH) {
    problems.push(`a name longer than ${MAX_DNS_NAME_LENGTH} characters`);
  }
  return problems;
}

function listed(items: string[]): string {
  return items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`;
}

/**
 * Normalizes an SSO domain to the authority the identity provider fetches the
 * discovery document from: lowercased and IDNA-encoded. A loopback host may
 * carry a port, for a local mock provider; any other host may not.
 *
 * @param domain - The organization domain.
 * @returns The normalized authority.
 * @throws When `domain` is not a domain, naming every problem with it.
 */
export function normalizeSsoDomain(domain: string): string {
  const trimmed = domain.trim();
  if (trimmed.length === 0) {
    throw new Error('ssoDomain cannot be empty');
  }
  const scheme = /^[a-z][a-z0-9+.-]*:\/\//i.exec(trimmed)?.[0];
  const rest = scheme === undefined ? trimmed : trimmed.slice(scheme.length);
  let url: URL;
  try {
    url = new URL(`https://${rest}`);
  } catch {
    throw new Error(`ssoDomain ${quote(trimmed)} is not a domain`);
  }
  const { username, password, pathname, hostname, port, host, href } = url;
  // `URL` drops an empty or default port such as `:443`, so the typed one is read
  // from the input itself.
  const typedAuthority = rest.split(/[/?#]/)[0] ?? '';
  const typedPort = /:([0-9]*)$/.exec(
    typedAuthority.slice(typedAuthority.lastIndexOf('@') + 1),
  )?.[1];
  const [beforeFragment = ''] = href.split('#');

  const problems: string[] = [];
  if (scheme !== undefined) problems.push('a scheme');
  if (username !== '' || password !== '') problems.push('userinfo');
  if (pathname !== '/') problems.push('a path');
  if (beforeFragment.includes('?')) problems.push('a query');
  if (href.includes('#')) problems.push('a fragment');
  const loopback = isLoopbackHost(hostname);
  if (typedPort !== undefined && !loopback) {
    problems.push('a port, which only loopback hosts may carry');
  } else if (typedPort !== undefined && (typedPort === '' || typedPort !== port)) {
    problems.push('an empty or default port');
  }
  if (trimmed.length > MAX_AUTHORITY_LENGTH) {
    problems.push(`more than ${MAX_AUTHORITY_LENGTH} characters`);
  } else if (!loopback) {
    problems.push(...dnsNameProblems(hostname));
  }
  if (problems.length > 0) {
    throw new Error(`ssoDomain ${quote(trimmed)} has ${listed(problems)}`);
  }
  return host;
}
