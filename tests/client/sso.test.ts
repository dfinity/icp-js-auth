import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { isValidSsoDomain } from '../../src/client/sso.ts';

const WELL_KNOWN_PATH = '/.well-known/ii-openid-configuration';

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
}

const validConfiguration = {
  client_id: 'ii-client',
  openid_configuration: 'https://idp.dfinity.org/.well-known/openid-configuration',
};

/** The signal is required, so a check that never aborts still needs one. */
function check(domain: string, signal = new AbortController().signal): Promise<boolean> {
  return isValidSsoDomain(domain, signal);
}

describe('isValidSsoDomain', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn().mockResolvedValue(jsonResponse(validConfiguration));
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('should accept a domain publishing an SSO configuration', async () => {
    await expect(check('dfinity.org')).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      `https://dfinity.org${WELL_KNOWN_PATH}`,
      expect.objectContaining({ headers: { Accept: 'application/json' } }),
    );
  });

  it('should normalize the domain before fetching', async () => {
    await expect(check('  DFINITY.org  ')).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      `https://dfinity.org${WELL_KNOWN_PATH}`,
      expect.anything(),
    );
  });

  it('should encode an internationalized domain', async () => {
    await expect(check('zürich.example')).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      `https://xn--zrich-kva.example${WELL_KNOWN_PATH}`,
      expect.anything(),
    );
  });

  it('should keep a non-default port', async () => {
    await expect(check('sso.dfinity.org:8443')).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      `https://sso.dfinity.org:8443${WELL_KNOWN_PATH}`,
      expect.anything(),
    );
  });

  it('should use http for a loopback host', async () => {
    await expect(check('localhost:11107')).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      `http://localhost:11107${WELL_KNOWN_PATH}`,
      expect.anything(),
    );
  });

  it.each([
    ['an empty domain', ''],
    ['a bare hostname', 'dfinity'],
    ['a domain carrying a scheme', 'https://dfinity.org'],
    ['a domain carrying a path', 'dfinity.org/sso'],
    ['a domain carrying a query', 'dfinity.org?x=1'],
    ['a domain carrying a fragment', 'dfinity.org#x'],
    ['a domain carrying userinfo', 'user:pw@dfinity.org'],
    ['a domain carrying a space', 'dfinity .org'],
    ['an authority over 255 characters', `${'a'.repeat(252)}.org`],
  ])('should reject %s without fetching', async (_case, domain) => {
    await expect(check(domain)).resolves.toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ['a non-200 response', jsonResponse(validConfiguration, { status: 404 })],
    ['a body that is not JSON', new Response('<html>nope</html>', { status: 200 })],
    ['a configuration without client_id', jsonResponse({ openid_configuration: 'https://x/y' })],
    ['a configuration without openid_configuration', jsonResponse({ client_id: 'ii-client' })],
    ['a configuration that is not an object', jsonResponse('ii-client')],
  ])('should reject %s', async (_case, response) => {
    fetchMock.mockResolvedValue(response);
    await expect(check('dfinity.org')).resolves.toBe(false);
  });

  it('should reject a domain the request cannot reach', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));
    await expect(check('dfinity.org')).resolves.toBe(false);
  });

  it('should require a signal', async () => {
    // @ts-expect-error the caller sets the deadline, so the signal is required
    await expect(isValidSsoDomain('dfinity.org')).rejects.toThrow();
  });

  it('should reject rather than resolve false when aborted', async () => {
    const controller = new AbortController();
    const pending = isValidSsoDomain('dfinity.org', controller.signal);
    controller.abort();
    await expect(pending).rejects.toThrow();
  });

  it('should reject an already-aborted check without fetching', async () => {
    await expect(isValidSsoDomain('dfinity.org', AbortSignal.abort())).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
