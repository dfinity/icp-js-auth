import { Principal } from '@icp-sdk/core/principal';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CookieStateStorage } from '../../src/client/cookie-state-storage.ts';
import {
  LocalStateStorage,
  MemoryStateStorage,
  type SessionState,
  type StateStorage,
} from '../../src/client/state-storage.ts';

// jsdom serves this document from localhost, and `document.cookie` is scoped by
// the document's own URL rather than by anything stubbed — so the tests write
// host-only cookies over the loopback path, as a local deployment does.
const DOMAIN = 'localhost';

// The key every call names, which the client takes from its own slots.
const KEY = 'ic-session-state';

const state = (msFromNow = 60 * 60 * 1000): Omit<SessionState, 'held'> => ({
  principal: Principal.selfAuthenticating(new Uint8Array([1, 2, 3])),
  expiration: (BigInt(Date.now()) + BigInt(msFromNow)) * 1_000_000n,
});

const clearCookies = () => {
  for (const entry of document.cookie.split(';')) {
    const name = entry.split('=')[0]?.trim();
    // biome-ignore lint/suspicious/noDocumentCookie: the store under test writes cookies synchronously, so the tests clear them the same way.
    if (name) document.cookie = `${name}=; Max-Age=0; Path=/`;
  }
};

beforeEach(() => {
  vi.unstubAllGlobals();
  vi.stubGlobal('location', { hostname: 'localhost', protocol: 'http:' });
  clearCookies();
});

afterEach(() => {
  clearCookies();
  vi.unstubAllGlobals();
});

describe('CookieStateStorage', () => {
  it('holds a state and gives it back', () => {
    const storage = new CookieStateStorage({ domain: DOMAIN });
    const written = state();
    expect(storage.get(KEY)).toBeNull();

    storage.set(KEY, written);
    expect(storage.get(KEY)).toEqual({ ...written, held: true });

    storage.remove(KEY);
    expect(storage.get(KEY)).toBeNull();
  });

  it('is read by another instance under the same key, which is what a sibling does', () => {
    new CookieStateStorage({ domain: DOMAIN }).set(KEY, state());

    expect(new CookieStateStorage({ domain: DOMAIN }).get(KEY)).not.toBeNull();
  });

  it('reports the sign-in as not held where this origin never acquired one', () => {
    const storage = new CookieStateStorage({ domain: DOMAIN });
    storage.set(KEY, state());
    expect(storage.get(KEY)?.held).toBe(true);

    // What a sibling subdomain sees: the same cookie, and no local record of
    // its own, because `localStorage` is per origin.
    localStorage.clear();

    expect(storage.get(KEY)?.held).toBe(false);
    expect(storage.get(KEY)).not.toBeNull();
  });

  it('does not read a record left from an earlier sign-in as holding this one', () => {
    const storage = new CookieStateStorage({ domain: DOMAIN });
    storage.set(KEY, state());
    expect(storage.get(KEY)?.held).toBe(true);

    // The cookie is replaced by a sibling signing in as someone else, while this
    // origin's own record — kept on purpose, so an app can say the session ended
    // — still names the account before it.
    // biome-ignore lint/suspicious/noDocumentCookie: as above.
    document.cookie = `${KEY}=${encodeURIComponent(
      `${Principal.selfAuthenticating(new Uint8Array([9, 9, 9])).toText()}|${
        (BigInt(Date.now()) + 3_600_000n) * 1_000_000n
      }`,
    )}; Path=/`;

    expect(storage.get(KEY)?.held).toBe(false);
  });

  it('discards this origin claim and leaves the cookie for the siblings', () => {
    const storage = new CookieStateStorage({ domain: DOMAIN });
    storage.set(KEY, state());

    storage.discard(KEY);

    expect(storage.get(KEY)?.held).toBe(false);
    expect(storage.get(KEY)).not.toBeNull();
  });

  it('keeps clients under different keys apart, which is what a namespace moves', () => {
    const storage = new CookieStateStorage({ domain: DOMAIN });
    storage.set('one:ic-session-state', state());

    expect(storage.get('two:ic-session-state')).toBeNull();
    expect(storage.get('one:ic-session-state')).not.toBeNull();
  });

  it('removes rather than writes a state whose expiry has already passed', () => {
    const storage = new CookieStateStorage({ domain: DOMAIN });
    storage.set(KEY, state());

    storage.set(KEY, state(-1000));

    expect(storage.get(KEY)).toBeNull();
  });

  it('refuses a domain this host cannot write, rather than writing nothing', () => {
    vi.stubGlobal('location', { hostname: 'app.example.com', protocol: 'https:' });

    expect(() => new CookieStateStorage({ domain: 'elsewhere.example' })).toThrow(
      /cannot be scoped to/,
    );
  });

  it('refuses a domain below this host, which a browser would ignore silently', () => {
    vi.stubGlobal('location', { hostname: 'app.example.com', protocol: 'https:' });

    expect(() => new CookieStateStorage({ domain: 'sibling.example.com' })).toThrow(
      /cannot be scoped to/,
    );
  });

  it('reads past a malformed cookie it did not write', () => {
    const storage = new CookieStateStorage({ domain: DOMAIN });
    // Any cookie on this domain lands in `document.cookie`, and a stray `%` in a
    // name makes decoding throw — before the name is even compared, so one
    // unrelated cookie could otherwise break every read.
    // biome-ignore lint/suspicious/noDocumentCookie: as above.
    document.cookie = '%bad=1; Path=/';

    expect(() => storage.get(KEY)).not.toThrow();
    expect(storage.get(KEY)).toBeNull();

    storage.set(KEY, state());
    expect(storage.get(KEY)).not.toBeNull();
  });

  it('reports nothing rather than throwing on a cookie it cannot read', () => {
    const storage = new CookieStateStorage({ domain: DOMAIN });
    // biome-ignore lint/suspicious/noDocumentCookie: as above.
    document.cookie = `${KEY}=nonsense; Path=/`;

    expect(storage.get(KEY)).toBeNull();
  });

  it('tells a subscriber when the state changes, and not when it has not', () => {
    const storage = new CookieStateStorage({ domain: DOMAIN });
    const listener = vi.fn();
    const unsubscribe = storage.subscribe(KEY, listener);

    storage.set(KEY, state());
    expect(listener).toHaveBeenCalledTimes(1);

    // A sibling signing out is a removal, seen by looking rather than by an event.
    storage.remove(KEY);
    expect(listener).toHaveBeenCalledTimes(2);

    document.dispatchEvent(new Event('visibilitychange'));
    expect(listener).toHaveBeenCalledTimes(2);

    unsubscribe();
    storage.set(KEY, state());
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it('tells a subscriber when this origin drops its claim, cookie untouched', () => {
    const storage = new CookieStateStorage({ domain: DOMAIN });
    const listener = vi.fn();
    storage.subscribe(KEY, listener);

    storage.set(KEY, state());
    expect(listener).toHaveBeenCalledTimes(1);
    expect(storage.get(KEY)?.held).toBe(true);

    // `discard` leaves the cookie standing on purpose — a sibling may have
    // written it a moment ago — so the only thing that changed is `held`. That
    // is still a change to the answer this origin gives, and the case the store
    // exists for: it is how a sibling subdomain learns it has to acquire its own
    // credential.
    storage.discard(KEY);

    expect(storage.get(KEY)?.held).toBe(false);
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it('hears another tab of this origin drop its claim', () => {
    const storage = new CookieStateStorage({ domain: DOMAIN });
    storage.set(KEY, state());
    const listener = vi.fn();
    storage.subscribe(KEY, listener);

    // What the other tab's `discard` does to the medium this one can see: the
    // cookie is shared and unchanged, and the per-origin half is a
    // `localStorage` key, which reaches here as a `storage` event.
    localStorage.removeItem(KEY);
    globalThis.dispatchEvent(new StorageEvent('storage', { key: KEY }));

    expect(storage.get(KEY)?.held).toBe(false);
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('notices a change made by a sibling, which raises no event of its own', () => {
    const storage = new CookieStateStorage({ domain: DOMAIN });
    const listener = vi.fn();
    storage.subscribe(KEY, listener);

    // As a sibling subdomain's write arrives: the cookie is simply there.
    // biome-ignore lint/suspicious/noDocumentCookie: as above.
    document.cookie = `${KEY}=${encodeURIComponent(
      `${state().principal.toText()}|${state().expiration}`,
    )}; Path=/`;
    expect(listener).not.toHaveBeenCalled();

    globalThis.dispatchEvent(new Event('focus'));

    expect(listener).toHaveBeenCalledTimes(1);
  });
});

describe('resumable', () => {
  it('is the one store that says a sign-in may be brought back', () => {
    // Read as the client reads it: through the interface, where the property is
    // optional and absent is the safe answer.
    const stores: StateStorage[] = [
      new MemoryStateStorage(),
      new LocalStateStorage(),
      new CookieStateStorage({ domain: 'localhost' }),
    ];

    // The cookie's record reaches past this origin, so a sibling arrives holding
    // no credential and needs the provider to have kept the session. The other
    // two are read by the origin that wrote them and nobody else.
    expect(stores.map((store) => store.resumable === true)).toEqual([false, false, true]);
  });
});
