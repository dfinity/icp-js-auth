import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SyncCookieStorage, SyncLocalStorage } from '../../src/client/sync-storage.ts';

const KEY = 'ic-delegation';

/** A real delegation chain, so `SyncCookieStorage` can derive its hint from it. */
async function makeChain(expiration?: Date): Promise<{ json: string; principal: string }> {
  const key = Ed25519KeyIdentity.generate();
  const chain = await DelegationChain.create(
    key,
    key.getPublicKey(),
    expiration ?? new Date(Date.now() + 60 * 60 * 1000),
  );
  const principal = Principal.selfAuthenticating(new Uint8Array(chain.publicKey)).toText();
  return { json: JSON.stringify(chain.toJSON()), principal };
}

/** Clears every cookie jsdom currently holds. */
function clearCookies(): void {
  for (const entry of document.cookie.split(';')) {
    const name = entry.split('=')[0]?.trim();
    // biome-ignore lint/suspicious/noDocumentCookie: test helper clears cookies synchronously.
    if (name) document.cookie = `${name}=; Max-Age=0; Path=/`;
  }
}

beforeEach(() => {
  localStorage.clear();
  clearCookies();
});

afterEach(() => {
  localStorage.clear();
  clearCookies();
});

describe('SyncLocalStorage', () => {
  it('round-trips a value', () => {
    const storage = new SyncLocalStorage();
    expect(storage.get(KEY)).toBeNull();
    storage.set(KEY, 'value');
    expect(storage.get(KEY)).toBe('value');
    storage.remove(KEY);
    expect(storage.get(KEY)).toBeNull();
  });

  it('notifies a subscriber when the key changes in another tab', () => {
    const storage = new SyncLocalStorage();
    const listener = vi.fn();
    const unsubscribe = storage.subscribe(KEY, listener);

    // A `storage` event models a write from another tab (the browser only fires
    // it in the *other* tabs, so jsdom never fires it for our own set()).
    window.dispatchEvent(new StorageEvent('storage', { key: KEY, storageArea: localStorage }));
    expect(listener).toHaveBeenCalledTimes(1);

    // A wholesale clear (key === null) counts too.
    window.dispatchEvent(new StorageEvent('storage', { key: null, storageArea: localStorage }));
    expect(listener).toHaveBeenCalledTimes(2);

    // An unrelated key does not.
    window.dispatchEvent(new StorageEvent('storage', { key: 'other', storageArea: localStorage }));
    expect(listener).toHaveBeenCalledTimes(2);

    unsubscribe();
    window.dispatchEvent(new StorageEvent('storage', { key: KEY, storageArea: localStorage }));
    expect(listener).toHaveBeenCalledTimes(2);
  });
});

describe('SyncCookieStorage', () => {
  // Loopback host so the cookie is host-only (no Domain attribute), which jsdom
  // accepts. The class treats localhost as a secure context without `Secure`.
  const make = () => new SyncCookieStorage({ domain: 'localhost' });

  it('keeps the chain in localStorage and announces a hint cookie', async () => {
    const { json, principal } = await makeChain();
    const storage = make();
    storage.set(KEY, json);

    expect(localStorage.getItem(KEY)).toBe(json);
    const hint = storage.readHint(KEY);
    expect(hint?.principal.toText()).toBe(principal);
    expect(hint?.expiresAtMs).toBeGreaterThan(Date.now());
    // The cookie carries the hint, never the chain.
    expect(document.cookie).toContain(KEY);
    expect(document.cookie).not.toContain('signature');
  });

  it('returns the chain while the hint cookie agrees', async () => {
    const { json } = await makeChain();
    const storage = make();
    storage.set(KEY, json);
    expect(storage.get(KEY)).toBe(json);
  });

  it('drops the local chain when the hint cookie is gone (signed out elsewhere)', async () => {
    const { json } = await makeChain();
    const storage = make();
    storage.set(KEY, json);

    // A sibling subdomain signed out: the shared cookie is gone, the per-origin
    // localStorage chain is not. get() treats the cookie as authoritative.
    clearCookies();
    expect(storage.get(KEY)).toBeNull();
    expect(localStorage.getItem(KEY)).toBeNull();
  });

  it('drops the local chain when the hint names a different principal', async () => {
    const a = await makeChain();
    const storage = make();
    storage.set(KEY, a.json);

    // A sibling switched identity: same cookie, different principal. The local
    // chain is stale.
    // biome-ignore lint/suspicious/noDocumentCookie: test simulates a sibling writing the shared cookie.
    document.cookie = `${KEY}=${encodeURIComponent(`${Principal.anonymous().toText()}|${Date.now() + 60_000}`)}; Path=/; SameSite=Lax`;
    expect(storage.get(KEY)).toBeNull();
    expect(localStorage.getItem(KEY)).toBeNull();
  });

  it('clears both stores on remove', async () => {
    const { json } = await makeChain();
    const storage = make();
    storage.set(KEY, json);
    storage.remove(KEY);
    expect(localStorage.getItem(KEY)).toBeNull();
    expect(storage.readHint(KEY)).toBeNull();
  });

  it('does not announce an already-expired chain', async () => {
    const { json } = await makeChain(new Date(Date.now() - 1000));
    const storage = make();
    storage.set(KEY, json);
    expect(storage.readHint(KEY)).toBeNull();
  });

  it('notifies a subscriber when the hint cookie changes on another subdomain', async () => {
    const { json } = await makeChain();
    const storage = make();
    const listener = vi.fn();
    const unsubscribe = storage.subscribe(KEY, listener);

    // Another subdomain wrote the shared cookie; `document.cookie` fires no
    // event, so a re-check on `pageshow` (tab shown again) catches it.
    storage.set(KEY, json); // writes the cookie
    window.dispatchEvent(new PageTransitionEvent('pageshow'));
    expect(listener).toHaveBeenCalled();

    const before = listener.mock.calls.length;
    unsubscribe();
    clearCookies();
    window.dispatchEvent(new PageTransitionEvent('pageshow'));
    expect(listener.mock.calls.length).toBe(before);
  });
});
