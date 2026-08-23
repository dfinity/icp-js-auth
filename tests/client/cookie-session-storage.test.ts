import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CookieSessionStorage } from '../../src/client/cookie-session-storage.ts';

async function testChain(): Promise<DelegationChain> {
  const key = Ed25519KeyIdentity.generate();
  return DelegationChain.create(key, key.getPublicKey(), new Date(Date.now() + 3.6e6));
}

const principalOf = (chain: DelegationChain): Principal =>
  Principal.selfAuthenticating(new Uint8Array(chain.publicKey));

// Clears every cookie the tests may have set.
function clearCookies() {
  for (const entry of document.cookie.split(';')) {
    const name = entry.split('=')[0]?.trim();
    // biome-ignore lint/suspicious/noDocumentCookie: test teardown clears cookies synchronously.
    if (name) document.cookie = `${name}=; Path=/; Max-Age=0`;
  }
}

beforeEach(() => {
  localStorage.clear();
  clearCookies();
});

describe('CookieSessionStorage', () => {
  it('refuses a domain the browser would silently ignore', () => {
    // jsdom serves these tests from localhost, so a public domain cannot apply.
    expect(() => new CookieSessionStorage({ domain: 'example.com' })).toThrow(
      /has to be this host or one above it/,
    );
  });

  it('accepts a domain above this host', () => {
    expect(() => new CookieSessionStorage({ domain: 'localhost' })).not.toThrow();
  });

  // `localhost` is loopback, so the cookie is host-only (no Domain attribute)
  // and accepted by jsdom over http.
  const newStorage = () => new CookieSessionStorage({ domain: 'localhost' });

  it('round-trips a delegation gated by a matching hint cookie', async () => {
    const storage = newStorage();
    const chain = await testChain();

    storage.set({ chain: chain });
    const restored = storage.get();

    expect(restored?.chain.toJSON()).toEqual(chain.toJSON());
  });

  it('writes a hint cookie naming the principal', async () => {
    const storage = newStorage();
    const chain = await testChain();

    storage.set({ chain: chain });
    const hint = storage.readHint();

    expect(hint?.principal.toText()).toBe(principalOf(chain).toText());
  });

  it('returns null and clears the chain when no hint cookie is present', async () => {
    const storage = newStorage();
    const chain = await testChain();
    // A chain in localStorage but no cookie: a sibling subdomain never announced
    // a session (or signed out), so this origin's chain is stale.
    localStorage.setItem(storage.key, JSON.stringify(chain.toJSON()));

    expect(storage.get()).toBeNull();
    expect(localStorage.getItem(storage.key)).toBeNull();
  });

  it('returns null and clears the chain when the hint names a different principal', async () => {
    const storage = newStorage();
    const chainA = await testChain();
    storage.set({ chain: chainA }); // cookie now names principal A

    // Another chain (principal B) lands in localStorage without updating the
    // cookie — the cookie is authoritative, so the mismatch is treated as stale.
    const chainB = await testChain();
    localStorage.setItem(storage.key, JSON.stringify(chainB.toJSON()));

    expect(storage.get()).toBeNull();
    expect(localStorage.getItem(storage.key)).toBeNull();
  });

  it('discard leaves the hint cookie for the siblings', async () => {
    const storage = newStorage();
    storage.set({ chain: await testChain() });

    storage.discard();

    // The session is this origin's to drop; the hint is the domain's, and a
    // sibling may have written it for a session that is perfectly good.
    expect(localStorage.getItem(storage.key)).toBeNull();
    expect(storage.readHint()).not.toBeNull();
  });

  it('removes both the chain and the hint cookie', async () => {
    const storage = newStorage();
    storage.set({ chain: await testChain() });

    storage.remove();

    expect(storage.get()).toBeNull();
    expect(storage.readHint()).toBeNull();
    expect(localStorage.getItem(storage.key)).toBeNull();
  });

  it('notifies on a same-origin change (storage event)', async () => {
    const storage = newStorage();
    const listener = vi.fn();
    storage.subscribe(listener);

    // A same-origin other tab wrote the delegation; the `storage` event carries
    // that change into this tab.
    const chain = await testChain();
    localStorage.setItem(storage.key, JSON.stringify(chain.toJSON()));
    globalThis.dispatchEvent(
      new StorageEvent('storage', { key: storage.key, storageArea: localStorage }),
    );

    expect(listener).toHaveBeenCalledOnce();
  });

  it('notifies when the hint cookie changes and the tab is shown', async () => {
    const storage = newStorage();
    const listener = vi.fn();
    storage.subscribe(listener);

    // A sibling subdomain writes the hint cookie; `document.cookie` fires no
    // event, so the re-check on `pageshow` surfaces it.
    // biome-ignore lint/suspicious/noDocumentCookie: simulates a sibling subdomain writing the hint cookie.
    document.cookie = `${storage.key}=${encodeURIComponent('aaaaa-aa|9999999999999')}; Path=/`;
    globalThis.dispatchEvent(new Event('pageshow'));

    expect(listener).toHaveBeenCalledOnce();
  });

  it('notifies when the hint cookie changes and the window regains focus', async () => {
    const storage = newStorage();
    const listener = vi.fn();
    storage.subscribe(listener);

    // Two visible windows: focus moves back to this one without a visibility
    // change, so `focus` is what surfaces the sibling's cookie write.
    // biome-ignore lint/suspicious/noDocumentCookie: simulates a sibling subdomain writing the hint cookie.
    document.cookie = `${storage.key}=${encodeURIComponent('aaaaa-aa|9999999999999')}; Path=/`;
    globalThis.dispatchEvent(new Event('focus'));

    expect(listener).toHaveBeenCalledOnce();
  });

  it('fires the listener once when one change reaches several sources', async () => {
    const storage = newStorage();
    const listener = vi.fn();
    storage.subscribe(listener);

    // A same-origin sign-in writes both localStorage and the hint cookie, so the
    // change arrives via both the `storage` event and the cookie watchers. The
    // snapshot comparison collapses them into a single notification.
    storage.set({ chain: await testChain() });
    globalThis.dispatchEvent(
      new StorageEvent('storage', { key: storage.key, storageArea: localStorage }),
    );
    globalThis.dispatchEvent(new Event('pageshow'));

    expect(listener).toHaveBeenCalledOnce();
  });

  it('does not fire when a trigger reflects no state change', () => {
    const storage = newStorage();
    const listener = vi.fn();
    storage.subscribe(listener);

    // A spurious event with nothing changed in localStorage or the cookie.
    globalThis.dispatchEvent(
      new StorageEvent('storage', { key: storage.key, storageArea: localStorage }),
    );
    globalThis.dispatchEvent(new Event('pageshow'));

    expect(listener).not.toHaveBeenCalled();
  });

  it('stops notifying after unsubscribe', async () => {
    const storage = newStorage();
    const listener = vi.fn();
    const unsubscribe = storage.subscribe(listener);

    unsubscribe();
    storage.set({ chain: await testChain() });
    globalThis.dispatchEvent(
      new StorageEvent('storage', { key: storage.key, storageArea: localStorage }),
    );
    globalThis.dispatchEvent(new Event('pageshow'));

    expect(listener).not.toHaveBeenCalled();
  });
});
