/**
 * Whether a hostname is loopback, which browsers treat as a secure context and
 * which means a local replica rather than a gateway on the network.
 */
export const isLoopbackHost = (hostname: string): boolean =>
  hostname === 'localhost' ||
  hostname.endsWith('.localhost') ||
  hostname === '127.0.0.1' ||
  hostname === '[::1]';
