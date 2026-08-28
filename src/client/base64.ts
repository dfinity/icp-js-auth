/**
 * Base64 for the JSON-RPC wire, which carries bytes as strings.
 *
 * Uses the built-in `Uint8Array` methods where the runtime has them, since they
 * are faster than a byte-at-a-time loop, and falls back where it does not.
 */
export function toBase64(bytes: Uint8Array): string {
  if ('toBase64' in bytes && typeof bytes.toBase64 === 'function') {
    return bytes.toBase64();
  }
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return globalThis.btoa(binary);
}

export function fromBase64(str: string): Uint8Array {
  if ('fromBase64' in Uint8Array && typeof Uint8Array.fromBase64 === 'function') {
    return Uint8Array.fromBase64(str);
  }
  const binary = globalThis.atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
