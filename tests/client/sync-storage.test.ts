import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SyncCookieStorage, SyncLocalStorage } from '../../src/client/sync-storage.ts';

const KEY = 'ic-delegation_expiration';

/**
 * Records what is assigned to `document.cookie` while still applying it.
 *
 * The attributes are the security-relevant part and cannot be read back:
 * `document.cookie` returns names and values only.
 */
function captureCookieWrites(): string[] {
  const writes: string[] = [];
  const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(document), 'cookie');
  if (descriptor?.get === undefined || descriptor.set === undefined) {
    throw new Error('document.cookie is not an accessor');
  }
  Object.defineProperty(document, 'cookie', {
    configurable: true,
    get: () => descriptor.get?.call(document),
    set: (value: string) => {
      writes.push(value);
      descriptor.set?.call(document, value);
    },
  });
  return writes;
}

const attributesOf = (write: string) => write.split('; ').slice(1);

/** Writes a cookie without going through the class under test. */
function setRawCookie(value: string): void {
  // biome-ignore lint/suspicious/noDocumentCookie: these tests exercise the document.cookie store itself.
  document.cookie = value;
}

beforeEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
});

afterEach(() => {
  // Drop the capture override, if the test installed one.
  delete (document as unknown as { cookie?: unknown }).cookie;
  for (const entry of document.cookie.split(';')) {
    const name = entry.split('=')[0]?.trim();
    if (name) setRawCookie(`${name}=; Path=/; Max-Age=0`);
  }
});

describe('SyncLocalStorage', () => {
  it('round-trips a value', () => {
    const storage = new SyncLocalStorage();
    expect(storage.get(KEY)).toBeNull();

    storage.set(KEY, '123');
    expect(storage.get(KEY)).toBe('123');
    expect(localStorage.getItem(KEY)).toBe('123');

    storage.remove(KEY);
    expect(storage.get(KEY)).toBeNull();
  });

  it('keeps a value whose expiry has passed, having no way to expire it', () => {
    const storage = new SyncLocalStorage();
    storage.set(KEY, '123', Date.now() - 1_000);
    expect(storage.get(KEY)).toBe('123');
  });
});

describe('SyncCookieStorage', () => {
  // jsdom serves the tests from localhost, so only a matching domain sticks.
  const testStorage = () => new SyncCookieStorage({ domain: 'localhost' });

  it('round-trips a value', () => {
    const storage = testStorage();
    expect(storage.get(KEY)).toBeNull();

    storage.set(KEY, '123');
    expect(storage.get(KEY)).toBe('123');

    storage.remove(KEY);
    expect(storage.get(KEY)).toBeNull();
  });

  it('reads its own value among other cookies', () => {
    setRawCookie('other=first; Path=/');
    setRawCookie('another=second; Path=/');
    const storage = testStorage();
    storage.set(KEY, '123');

    expect(storage.get(KEY)).toBe('123');
    expect(storage.get('other')).toBe('first');
    expect(storage.get('missing')).toBeNull();
  });

  it('expires with the value it describes', () => {
    const writes = captureCookieWrites();
    testStorage().set(KEY, '123', Date.now() + 60_000);

    expect(attributesOf(writes[0])).toContain('Max-Age=60');
  });

  it('removes rather than writes a value whose expiry has passed', () => {
    const storage = testStorage();
    storage.set(KEY, '123');
    storage.set(KEY, '456', Date.now() - 1_000);

    expect(storage.get(KEY)).toBeNull();
  });

  it('omits Domain on loopback, where a host-only cookie already spans ports', () => {
    const writes = captureCookieWrites();
    testStorage().set(KEY, '123');

    expect(writes[0]).not.toContain('Domain=');
    expect(attributesOf(writes[0])).toEqual(expect.arrayContaining(['Path=/', 'SameSite=Lax']));
  });

  it('scopes the cookie to the domain so subdomains share it', () => {
    const writes = captureCookieWrites();
    new SyncCookieStorage({ domain: 'example.com' }).set(KEY, '123');

    expect(attributesOf(writes[0])).toContain('Domain=example.com');
  });

  it('marks the cookie Secure over https', () => {
    vi.stubGlobal('location', { protocol: 'https:' });
    const writes = captureCookieWrites();
    new SyncCookieStorage({ domain: 'example.com' }).set(KEY, '123');

    expect(attributesOf(writes[0])).toContain('Secure');
  });

  it('omits Secure on loopback, where it is not reliably accepted', () => {
    const writes = captureCookieWrites();
    testStorage().set(KEY, '123');

    expect(attributesOf(writes[0])).not.toContain('Secure');
  });

  it('removes with the same attributes, so the write targets the same cookie', () => {
    const writes = captureCookieWrites();
    const storage = new SyncCookieStorage({ domain: 'example.com' });
    storage.set(KEY, '123');
    storage.remove(KEY);

    expect(attributesOf(writes[1])).toEqual(
      expect.arrayContaining(['Domain=example.com', 'Path=/', 'Max-Age=0']),
    );
  });
});
