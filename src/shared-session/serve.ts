import { Principal } from '@icp-sdk/core/principal';
import { type AuthClientStorage, IdbStorage } from '../client/storage.js';
import {
  ALTERNATIVE_ORIGINS_PATH,
  CHANNEL,
  isChannelMessage,
  isLoopbackHost,
  MAX_ALTERNATIVE_ORIGINS,
  OPS,
  PROTOCOL_VERSION,
  parseBareOrigin,
  type SharedSessionOp,
  type SharedSessionRequest,
  type SharedSessionResponse,
} from './protocol.js';

export interface ServeSharedSessionOptions {
  /**
   * Derivation origin whose session this hub holds.
   *
   * Its `/.well-known/ii-alternative-origins` record decides which origins may
   * read the session. Clients must sign in with this same value.
   */
  derivationOrigin: string | URL;

  /**
   * Store holding the shared session.
   * @default IdbStorage
   */
  storage?: AuthClientStorage;

  /**
   * Replaces discovery of the allow-list. Intended for tests and for
   * deployments that publish the record elsewhere.
   *
   * The returned origins are the only ones served, alongside the derivation
   * origin itself.
   */
  allowedOrigins?: () => Promise<string[]>;
}

/**
 * Serves the shared session to the origins authorized by this origin.
 *
 * Call this on load from a page deployed at the URL clients pass to
 * `SharedSessionStorage`. The page needs nothing else: no markup, no user
 * interaction, and no state of its own.
 *
 * The page may be served from any origin; the derivation origin decides which
 * origins may read the session, through its
 * `/.well-known/ii-alternative-origins` record.
 *
 * Serve it with a `Content-Security-Policy: frame-ancestors` header naming the
 * origins allowed to embed it. That is defence in depth — the allow-list below
 * is what authorizes a reader — but it stops an unrelated site from loading the
 * page at all.
 *
 * @param options - See {@link ServeSharedSessionOptions}.
 * @returns A function that stops serving.
 *
 * @example
 * ```ts
 * import { serveSharedSession } from '@icp-sdk/auth/shared-session';
 *
 * serveSharedSession({ derivationOrigin: 'https://auth.example.com' });
 * ```
 */
export function serveSharedSession(options: ServeSharedSessionOptions): () => void {
  const storage = options.storage ?? new IdbStorage();
  const derivationOrigin = new URL(options.derivationOrigin.toString()).origin;
  const discover = options.allowedOrigins ?? (() => fetchAlternativeOrigins(derivationOrigin));

  let discovered: Promise<Set<string>> | null = null;
  // Memoized, but a failure is not cached: a transient error must not deny every
  // client until this page reloads.
  const allowedOrigins = (): Promise<Set<string>> => {
    if (discovered === null) {
      const pending = discover().then(
        (origins) =>
          new Set(
            [derivationOrigin, ...origins]
              .map((origin) => parseBareOrigin(origin)?.origin)
              .filter((origin): origin is string => origin !== undefined),
          ),
      );
      pending.catch(() => {
        if (discovered === pending) {
          discovered = null;
        }
      });
      discovered = pending;
    }
    return discovered;
  };

  const onMessage = async (event: MessageEvent): Promise<void> => {
    const source = event.source as Window | null;
    if (source === null || !isChannelMessage(event.data)) return;

    const request = event.data as Partial<SharedSessionRequest>;
    // A ready announcement or a future hub-initiated push is not a request.
    if (request.id === undefined) return;

    const origin = event.origin;
    const reply = (body: Partial<SharedSessionResponse>): void => {
      const response: SharedSessionResponse = {
        v: PROTOCOL_VERSION,
        type: CHANNEL,
        id: request.id as number,
        ...body,
      };
      source.postMessage(response, origin);
    };

    if (request.v !== PROTOCOL_VERSION) {
      reply({
        error: `unsupported protocol version ${String(request.v)}, this hub speaks ${PROTOCOL_VERSION}`,
      });
      return;
    }

    const permitted = await allowedOrigins()
      .then((origins) => origins.has(origin))
      .catch(() => false);
    const op = request.op;
    if (!permitted || op === undefined || !OPS.includes(op) || typeof request.key !== 'string') {
      reply({ error: 'denied' });
      return;
    }

    try {
      reply({ result: await apply(storage, op, request.key, request.value) });
    } catch (error) {
      reply({ error: `${op} failed: ${String(error)}` });
    }
  };

  const listener = (event: MessageEvent): void => {
    void onMessage(event);
  };
  addEventListener('message', listener);

  // Announced to whoever embeds this page: it carries no session data, and the
  // embedder's origin cannot be known until it identifies itself.
  parent.postMessage({ v: PROTOCOL_VERSION, type: CHANNEL, ready: true }, '*');

  return () => removeEventListener('message', listener);
}

async function apply(
  storage: AuthClientStorage,
  op: SharedSessionOp,
  key: string,
  value: SharedSessionRequest['value'],
): Promise<SharedSessionResponse['result']> {
  switch (op) {
    case 'get':
      return await storage.get(key);
    case 'set':
      if (value === undefined) throw new Error('set requires a value');
      await storage.set(key, value);
      return null;
    case 'remove':
      await storage.remove(key);
      return null;
  }
}

async function fetchAlternativeOrigins(derivationOrigin: string): Promise<string[]> {
  const url = await alternativeOriginsUrl(derivationOrigin);
  const response = await fetch(url, {
    // A redirect would move the record to an origin that never vouched for it.
    redirect: 'error',
    credentials: 'omit',
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`${url} returned status ${response.status}`);
  }

  const record = (await response.json()) as { alternativeOrigins?: unknown };
  if (!Array.isArray(record?.alternativeOrigins)) {
    throw new Error(`${url} has no alternativeOrigins array`);
  }
  if (record.alternativeOrigins.length > MAX_ALTERNATIVE_ORIGINS) {
    throw new Error(
      `${url} lists more than ${MAX_ALTERNATIVE_ORIGINS} origins, which Internet Identity rejects`,
    );
  }
  return record.alternativeOrigins;
}

/**
 * The official HTTP gateway.
 *
 * A request to a canister-id subdomain of it passes a boundary node that
 * verifies asset certification; a custom domain carries no such guarantee.
 */
const IC_HTTP_GATEWAY_DOMAIN = 'icp0.io';

/** Domains where the canister id is the leftmost label of the hostname. */
const WELL_KNOWN_IC_DOMAINS = [
  'ic0.app',
  'icp0.io',
  'icp.net',
  'internetcomputer.org',
  'localhost',
];

/** Header a boundary node sets to name the canister serving a custom domain. */
const CANISTER_ID_HEADER = 'x-ic-canister-id';

/**
 * Where to read the derivation origin's record from.
 *
 * Read through the canister-id gateway URL rather than the derivation origin's
 * own domain, so a boundary node verifies certification — the same precaution
 * Internet Identity takes when it validates a derivation origin. Reading the
 * custom domain directly would let anyone able to tamper with its responses
 * widen the set of origins allowed to read the session.
 * @param derivationOrigin - Origin whose record is wanted.
 */
async function alternativeOriginsUrl(derivationOrigin: string): Promise<string> {
  // This page's own origin: the record's integrity is already this page's, so
  // anyone able to rewrite it can rewrite this bundle and the gateway adds
  // nothing.
  if (derivationOrigin === location.origin) {
    return ALTERNATIVE_ORIGINS_PATH;
  }

  const url = new URL(derivationOrigin);
  const canisterId = await resolveCanisterId(url);

  // A local replica serves every canister from one host, so the canister is
  // named by query parameter instead of by subdomain.
  if (isLoopbackHost(url.hostname)) {
    return `${url.origin}${ALTERNATIVE_ORIGINS_PATH}?canisterId=${canisterId.toText()}`;
  }
  return `https://${canisterId.toText()}.${IC_HTTP_GATEWAY_DOMAIN}${ALTERNATIVE_ORIGINS_PATH}`;
}

/**
 * Resolves the canister serving an origin.
 *
 * On a well-known IC domain the canister id is the leftmost label. A custom
 * domain has to be asked: a boundary node answers with the canister id in a
 * response header. That header is not certified, so a party able to tamper with
 * the origin's responses can name a canister of their own — the certified read
 * that follows then verifies the wrong canister's record. Internet Identity
 * resolves the same way and inherits the same limit.
 * @param origin - Origin to resolve.
 */
async function resolveCanisterId(origin: URL): Promise<Principal> {
  const fromHostname = canisterIdFromHostname(origin.hostname);
  if (fromHostname !== undefined) {
    return fromHostname;
  }

  const response = await fetch(origin.origin, { method: 'HEAD', credentials: 'omit' });
  const header = response.headers.get(CANISTER_ID_HEADER);
  if (header === null) {
    throw new Error(`${origin.origin} did not answer with a ${CANISTER_ID_HEADER} header`);
  }
  try {
    return Principal.fromText(header);
  } catch {
    throw new Error(`${origin.origin} answered with an invalid ${CANISTER_ID_HEADER}: "${header}"`);
  }
}

function canisterIdFromHostname(hostname: string): Principal | undefined {
  // Matched on a dot boundary, so a lookalike such as `evil-ic0.app` is not
  // taken for a well-known IC domain.
  const wellKnown = WELL_KNOWN_IC_DOMAINS.some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
  );
  if (!wellKnown) return undefined;

  const [first, ...rest] = hostname.split('.');
  // No subdomain to read a canister id from.
  if (rest.length === 0) return undefined;
  try {
    return Principal.fromText(first);
  } catch {
    // Not a canister id, so the origin is a custom domain on one of these hosts
    // and has to be asked instead.
    return undefined;
  }
}
