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

/**
 * The official HTTP gateway.
 *
 * Requests to a canister-id subdomain of this domain pass a boundary node that
 * verifies asset certification; a custom domain does not carry that guarantee.
 */
const IC_HTTP_GATEWAY_DOMAIN = 'icp0.io';

export interface ServeSharedSessionOptions {
  /**
   * Derivation origin whose session this hub holds.
   *
   * Its `/.well-known/ii-alternative-origins` record lists the origins allowed
   * to read the session. Those origins must sign in with this same derivation
   * origin, or they store a session for a principal the others are not
   * authorized for.
   */
  derivationOrigin: string | URL;

  /**
   * Canister id serving the derivation origin.
   *
   * Only used when the derivation origin is a different origin than this page.
   * Supplying it makes the allow-list read through the official gateway, which
   * verifies certification — without it, anyone able to tamper with responses
   * from the derivation origin can widen the set of readers. Internet Identity
   * takes the same precaution when it validates a derivation origin.
   */
  canisterId?: string;

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
 * Serves the shared session to the origins authorized by the derivation origin.
 *
 * Call this on load from a page deployed at the URL clients pass to
 * `SharedSessionStorage`. The page needs nothing else: no markup, no user
 * interaction, and no state of its own.
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
 * serveSharedSession({
 *   derivationOrigin: 'https://auth.example.com',
 *   canisterId: 'rdmx6-jaaaa-aaaaa-aaadq-cai',
 * });
 * ```
 */
export function serveSharedSession(options: ServeSharedSessionOptions): () => void {
  const storage = options.storage ?? new IdbStorage();
  const derivationOrigin = new URL(options.derivationOrigin.toString()).origin;
  if (options.canisterId !== undefined) {
    try {
      Principal.fromText(options.canisterId);
    } catch {
      throw new Error(
        `Shared session canisterId is not a valid principal: "${options.canisterId}".`,
      );
    }
  }
  const discover =
    options.allowedOrigins ?? (() => fetchAlternativeOrigins(derivationOrigin, options.canisterId));

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

async function fetchAlternativeOrigins(
  derivationOrigin: string,
  canisterId: string | undefined,
): Promise<string[]> {
  const url = alternativeOriginsUrl(derivationOrigin, canisterId);
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

function alternativeOriginsUrl(derivationOrigin: string, canisterId: string | undefined): string {
  // Same origin: the record's integrity is this page's own. Anyone able to
  // rewrite it can rewrite this bundle, so the gateway adds nothing.
  if (derivationOrigin === location.origin) {
    return ALTERNATIVE_ORIGINS_PATH;
  }
  if (canisterId !== undefined) {
    return `https://${canisterId}.${IC_HTTP_GATEWAY_DOMAIN}${ALTERNATIVE_ORIGINS_PATH}`;
  }
  if (!isLoopbackHost(new URL(derivationOrigin).hostname)) {
    console.warn(
      `Reading ${derivationOrigin}${ALTERNATIVE_ORIGINS_PATH} without certification. Pass canisterId so the allow-list is read through ${IC_HTTP_GATEWAY_DOMAIN}, otherwise tampering with that origin's responses can widen who may read the shared session.`,
    );
  }
  return `${derivationOrigin}${ALTERNATIVE_ORIGINS_PATH}`;
}
