import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { isValidSsoDomain } from '../../src/client/sso.ts';

const WELL_KNOWN_PATH = '/.well-known/ii-openid-configuration';

const MIN_DURATION_MS = 750;

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

/** Resolves the check with its duration floor advanced, so no test waits in real time. */
async function check(domain: string, signal?: AbortSignal): Promise<boolean> {
  const pending = isValidSsoDomain(domain, signal);
  await vi.advanceTimersByTimeAsync(MIN_DURATION_MS);
  return pending;
}

describe('isValidSsoDomain', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    fetchMock = vi.fn().mockResolvedValue(jsonResponse(validConfiguration));
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.useRealTimers();
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
    await expect(check('中国.cn')).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      `https://xn--fiqs8s.cn${WELL_KNOWN_PATH}`,
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

  it('should not resolve before the minimum duration', async () => {
    const settled = vi.fn();
    void isValidSsoDomain('dfin').then(settled);

    await vi.advanceTimersByTimeAsync(MIN_DURATION_MS - 1);
    expect(settled).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(settled).toHaveBeenCalledWith(false);
  });

  it('should reject rather than resolve false when aborted', async () => {
    const controller = new AbortController();
    const pending = isValidSsoDomain('dfinity.org', controller.signal);
    controller.abort();
    await expect(pending).rejects.toThrow();
  });

  it('should reject an already-aborted check without waiting out the floor', async () => {
    await expect(isValidSsoDomain('dfinity.org', AbortSignal.abort())).rejects.toThrow();
  });
});
