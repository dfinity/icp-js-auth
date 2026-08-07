import type { StoredKey } from '../client/storage.js';

/** Discriminator for every message exchanged between a client and the hub. */
export const CHANNEL = 'icp-auth-shared-session';

/**
 * Wire protocol version.
 *
 * A client and a hub are deployed separately and can run different versions of
 * this package, so both sides check it and refuse a mismatch instead of
 * misreading each other's payloads.
 */
export const PROTOCOL_VERSION = 1;

/** Path of the Internet Identity alternative origins record, relative to the derivation origin. */
export const ALTERNATIVE_ORIGINS_PATH = '/.well-known/ii-alternative-origins';

/** Internet Identity refuses a record with more entries than this. */
export const MAX_ALTERNATIVE_ORIGINS = 10;

/** Default time to wait for the hub to answer, in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 10_000;

export const OPS = ['get', 'set', 'remove'] as const;

export type SharedSessionOp = (typeof OPS)[number];

/** A storage operation, sent from a client to the hub. */
export interface SharedSessionRequest {
  v: number;
  type: typeof CHANNEL;
  id: number;
  op: SharedSessionOp;
  key: string;
  value?: StoredKey;
  /**
   * The client's derivation origin. The hub compares it against its own
   * configuration and refuses a mismatch: the two sides disagreeing means the
   * hub is enforcing an allow-list belonging to a different identity.
   */
  derivationOrigin: string;
}

/** The hub's answer to a {@link SharedSessionRequest}. */
export interface SharedSessionResponse {
  v: number;
  type: typeof CHANNEL;
  id: number;
  result?: StoredKey | null;
  error?: string;
}

/**
 * Sent by the hub once it is listening.
 *
 * Messages without an `id` are reserved for hub-initiated pushes, so a client
 * that meets a future one ignores it rather than failing to parse it.
 */
export interface SharedSessionReady {
  v: number;
  type: typeof CHANNEL;
  ready: true;
}

export function isChannelMessage(data: unknown): data is { v: unknown; type: typeof CHANNEL } {
  return typeof data === 'object' && data !== null && (data as { type?: unknown }).type === CHANNEL;
}

/** Whether a hostname is loopback, which browsers treat as a secure context. */
export function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname === '127.0.0.1' ||
    hostname === '[::1]'
  );
}

/**
 * Whether an origin may carry credentials over this protocol.
 *
 * `https` only, except for loopback, which local development depends on.
 */
export function isSecureOrigin(url: URL): boolean {
  if (url.protocol === 'https:') return true;
  return url.protocol === 'http:' && isLoopbackHost(url.hostname);
}

/**
 * Parses a bare origin.
 *
 * Returns `null` unless the value is a secure origin with nothing else attached:
 * a path, query, fragment, or embedded credentials means the entry is not the
 * plain origin it is required to be, and comparing it as one would be wrong.
 */
export function parseBareOrigin(value: unknown): URL | null {
  if (typeof value !== 'string') return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.origin !== value || !isSecureOrigin(url)) return null;
  return url;
}
