import type { SignIdentity } from '@icp-sdk/core/agent';
import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SessionGoneError } from '../../src/client/app-delegation-source.ts';
import { APP_SLOT, type CredentialStorage } from '../../src/client/credential-storage.ts';
import { MemoryCredentialStorage } from '../../src/client/memory-credential-storage.ts';
import { SessionIdentity } from '../../src/client/session-identity.ts';

const MINUTE = 60_000;
const TTL = 5 * MINUTE;

const accountKey = Ed25519KeyIdentity.generate();
const accountDer = accountKey.getPublicKey().toDer();

/**
 * A chain rooted at the account key and delegating to `to`, as the canister mints
 * them. The identity refuses one that does not authorise the key it made, so the
 * key has to be threaded through.
 */
async function appDelegation(to: SignIdentity, lifetimeMs = TTL): Promise<DelegationChain> {
  const chain = await DelegationChain.create(
    accountKey,
    to.getPublicKey(),
    new Date(Date.now() + lifetimeMs),
  );
  return DelegationChain.fromDelegations(chain.delegations, accountDer);
}

function harness(
  options: {
    slot?: string;
    beforeMint?: () => Promise<void>;
    lifetimeMs?: number;
    sessionMs?: number;
    onSessionGone?: () => void;
    storage?: CredentialStorage;
  } = {},
) {
  // The key a mint is for comes from the store, so the fake source has to sign
  // its answer to whatever key it was handed.
  const keys: SignIdentity[] = [];
  const inner = options.storage ?? new MemoryCredentialStorage();
  const storage: CredentialStorage = {
    shared: inner.shared,
    durable: inner.durable,
    create: vi.fn(async () => {
      const key = Ed25519KeyIdentity.generate();
      keys.push(key);
      return key;
    }),
    get: (slot) => inner.get(slot),
    set: (slot, credential) => inner.set(slot, credential as never),
    remove: (slot) => inner.remove(slot),
  };
  const newKey = storage.create;
  const mint = vi.fn(async (der: Uint8Array) => {
    await options.beforeMint?.();
    const key = keys.find((candidate) =>
      new Uint8Array(candidate.getPublicKey().toDer()).every((b, i) => b === der[i]),
    );
    if (!key) throw new Error('minted for a key the identity never made');
    return appDelegation(key, options.lifetimeMs ?? TTL);
  });
  const onSessionGone = options.onSessionGone ?? vi.fn();
  const identity = new SessionIdentity({
    accountKey: accountDer,
    sessionExpiresAtMs: Date.now() + (options.sessionMs ?? 30 * MINUTE),
    source: { mint },
    storage,
    slot: options.slot ?? APP_SLOT,
    onSessionGone,
  });
  const request = () =>
    identity.transformRequest({ body: { arg: new Uint8Array() } } as never) as Promise<unknown>;
  return { identity, mint, newKey, onSessionGone, request, storage, inner };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  vi.useRealTimers();
  // Not at the end of a test body: an assertion that throws first would leave a
  // stubbed `navigator` behind for whatever runs next.
  vi.unstubAllGlobals();
});

describe('SessionIdentity', () => {
  it('is a DelegationIdentity, so existing consumers accept it', () => {
    const { identity } = harness();
    expect(identity).toBeInstanceOf(SessionIdentity);
    expect(identity.getPublicKey().toDer()).toEqual(accountDer);
  });

  it('answers for the account principal before anything is minted', () => {
    const { identity, mint } = harness();
    expect(identity.getPrincipal().toText()).toBe(accountKey.getPrincipal().toText());
    expect(mint).not.toHaveBeenCalled();
  });

  it('mints on the first request and reuses it for later ones', async () => {
    const { mint, request } = harness();
    await request();
    await request();
    expect(mint).toHaveBeenCalledTimes(1);
  });

  it('serves concurrent requests from one mint', async () => {
    const { mint, request } = harness();
    await Promise.all([request(), request(), request()]);
    expect(mint).toHaveBeenCalledTimes(1);
  });

  it('signs with the delegation it holds', async () => {
    const { identity, request } = harness();
    const transformed = (await request()) as { body: { sender_delegation: unknown[] } };
    expect(transformed.body.sender_delegation).toEqual(identity.getDelegation().delegations);
  });

  it('replaces the delegation on schedule when it was used', async () => {
    const { mint, request } = harness();
    await request();

    await vi.advanceTimersByTimeAsync(TTL - 15_000);

    expect(mint).toHaveBeenCalledTimes(2);
  });

  it('keeps the account principal across a rotation', async () => {
    const { identity, mint, request } = harness();
    await request();
    const before = identity.getPrincipal().toText();

    await vi.advanceTimersByTimeAsync(TTL - 15_000);

    // Asserted so this cannot pass by no rotation having happened.
    expect(mint).toHaveBeenCalledTimes(2);
    // The delegation underneath was replaced; who is signed in was not.
    expect(identity.getPrincipal().toText()).toBe(before);
  });

  it('mints again after a failed mint rather than replaying the rejection', async () => {
    const { mint, request } = harness();
    mint.mockRejectedValueOnce(new Error('transport blip'));

    await expect(request()).rejects.toThrow('transport blip');

    await expect(request()).resolves.toBeDefined();
    expect(mint).toHaveBeenCalledTimes(2);
  });

  it('lets an unused delegation lapse instead of refreshing it', async () => {
    const { mint, request } = harness();
    await request();

    // The first delegation served a request, so it earns one refresh. The
    // replacement serves none, so it earns nothing.
    await vi.advanceTimersByTimeAsync(TTL - 15_000);
    await vi.advanceTimersByTimeAsync(TTL);

    expect(mint).toHaveBeenCalledTimes(2);
  });

  it('serves a request from a delegation inside the threshold and mints behind it', async () => {
    const { mint, identity, request } = harness();
    await request();
    const first = identity.getDelegation();
    identity.dispose(); // isolate the request path from the schedule

    await vi.advanceTimersByTimeAsync(TTL - 12_000);
    const transformed = (await request()) as { body: { sender_delegation: unknown[] } };

    expect(transformed.body.sender_delegation).toEqual(first.delegations);
    expect(mint).toHaveBeenCalledTimes(2);
  });

  it('waits for a mint when the delegation is inside the block margin', async () => {
    const { mint, identity, request } = harness();
    await request();
    const first = identity.getDelegation();
    identity.dispose();

    await vi.advanceTimersByTimeAsync(TTL - 5_000);
    const transformed = (await request()) as { body: { sender_delegation: unknown[] } };

    expect(mint).toHaveBeenCalledTimes(2);
    expect(transformed.body.sender_delegation).not.toEqual(first.delegations);
  });

  it('refresh() mints when one is due', async () => {
    const { mint, identity, request } = harness();
    await request();
    identity.dispose();

    await vi.advanceTimersByTimeAsync(TTL - 12_000);
    await identity.refresh();

    expect(mint).toHaveBeenCalledTimes(2);
  });

  it('refresh() does nothing when the delegation is healthy', async () => {
    const { mint, identity, request } = harness();
    await request();
    await identity.refresh();
    expect(mint).toHaveBeenCalledTimes(1);
  });

  it('reports a gone session once, and only for NoMatchingSession', async () => {
    const onSessionGone = vi.fn();
    const { mint, request } = harness({ onSessionGone });
    mint.mockRejectedValue(new SessionGoneError());

    await expect(request()).rejects.toThrow(SessionGoneError);
    await expect(request()).rejects.toThrow(SessionGoneError);

    expect(onSessionGone).toHaveBeenCalledTimes(1);
  });

  it('keeps the session when a mint fails for any other reason', async () => {
    const onSessionGone = vi.fn();
    const { mint, request } = harness({ onSessionGone });
    mint.mockRejectedValue(new Error('boundary node unreachable'));

    await expect(request()).rejects.toThrow('boundary node unreachable');

    expect(onSessionGone).not.toHaveBeenCalled();
  });

  it('does not mint against a session with nothing left, and reports it gone', async () => {
    const onSessionGone = vi.fn();
    const { mint, request } = harness({ sessionMs: 5_000, onSessionGone });

    await expect(request()).rejects.toThrow(SessionGoneError);

    expect(mint).not.toHaveBeenCalled();
    expect(onSessionGone).toHaveBeenCalledTimes(1);
  });

  it('refuses a delegation rooted at another account', async () => {
    const { mint, request } = harness();
    const other = Ed25519KeyIdentity.generate();
    const foreign = await DelegationChain.create(
      other,
      Ed25519KeyIdentity.generate().getPublicKey(),
      new Date(Date.now() + TTL),
    );
    mint.mockResolvedValue(foreign);

    await expect(request()).rejects.toThrow('not for this account and key');
  });

  it('refuses a delegation issued to a key it did not make', async () => {
    const { mint, request } = harness();
    // Rooted at the right account, but authorising somebody else's key.
    const strangersKey = Ed25519KeyIdentity.generate();
    mint.mockResolvedValue(await appDelegation(strangersKey));

    await expect(request()).rejects.toThrow('not for this account and key');
  });

  it('makes a fresh key for every mint, so a key never outlives its delegation', async () => {
    const { newKey, request } = harness();
    await request();

    await vi.advanceTimersByTimeAsync(TTL - 15_000);

    expect(newKey).toHaveBeenCalledTimes(2);
  });

  it('persists what it mints, so another tab of this origin can use it', async () => {
    const { identity, request, inner } = harness();
    await request();

    const stored = await inner.get(APP_SLOT);
    expect(stored?.chain?.toJSON()).toEqual(identity.getDelegation().toJSON());
  });

  it('adopts what the store already holds instead of minting', async () => {
    const first = harness();
    await first.request();
    const shared = first.inner;

    // A second identity over the same store: what the first tab minted is what
    // this one uses, without a call of its own.
    const second = harness({ storage: shared });
    await second.request();

    expect(second.mint).not.toHaveBeenCalled();
    expect(second.identity.getDelegation().toJSON()).toEqual(
      first.identity.getDelegation().toJSON(),
    );
  });

  it('mints when the store holds one too close to expiry to adopt', async () => {
    const first = harness({ lifetimeMs: 20_000 });
    await first.request();

    vi.advanceTimersByTime(10_000); // inside the pre-mint threshold

    const second = harness({ storage: first.inner });
    await second.request();

    expect(second.mint).toHaveBeenCalledOnce();
  });

  it('ignores a stored credential rooted at another account', async () => {
    const other = Ed25519KeyIdentity.generate();
    const key = Ed25519KeyIdentity.generate();
    const foreign = await DelegationChain.create(
      other,
      key.getPublicKey(),
      new Date(Date.now() + TTL),
    );
    const storage = new MemoryCredentialStorage();
    await storage.set(APP_SLOT, { identity: key as never, chain: foreign });

    const { request, mint } = harness({ storage });
    await request();

    // Not adopted, so it minted for itself rather than signing as someone else.
    expect(mint).toHaveBeenCalledOnce();
  });

  it('writes nothing when a sign-out takes the lock away mid-mint', async () => {
    const holders: ((error: Error) => void)[] = [];
    let steal!: () => void;
    const request = vi.fn(
      (_name: string, optionsOrRun: unknown, maybeRun?: () => unknown) =>
        new Promise((resolve, reject) => {
          const run = (
            typeof optionsOrRun === 'function' ? optionsOrRun : maybeRun
          ) as () => unknown;
          holders.push(reject);
          steal = () => {
            for (const holder of holders) holder(new DOMException('lock stolen', 'AbortError'));
          };
          void Promise.resolve().then(run).then(resolve, reject);
        }),
    );
    vi.stubGlobal('navigator', { locks: { request } });

    const storage = new MemoryCredentialStorage();
    Object.defineProperty(storage, 'shared', { value: true });
    const onSessionGone = vi.fn();

    // Two gates rather than counted microtasks: one says the mint is genuinely in
    // flight, the other lets it finish. Nothing here depends on scheduling.
    let mintStarted!: () => void;
    const inFlight = new Promise<void>((resolve) => {
      mintStarted = resolve;
    });
    let releaseMint!: () => void;
    const heldOpen = new Promise<void>((resolve) => {
      releaseMint = resolve;
    });

    const harnessed = harness({
      storage,
      onSessionGone,
      // Held open where a real mint waits on its two canister calls.
      beforeMint: () => {
        mintStarted();
        return heldOpen;
      },
    });

    const pending = harnessed.request().catch(() => undefined);
    await inFlight;
    steal();
    releaseMint();
    await pending;

    // The sign-out cleared this slot already. A credential written now would be
    // one minted under a session that has ended, and the next load would adopt
    // it.
    expect(await storage.get(APP_SLOT)).toBeNull();
    expect(onSessionGone).toHaveBeenCalledTimes(1);
  });

  it('removes a stored credential whose delegation has run out', async () => {
    const storage = new MemoryCredentialStorage();
    Object.defineProperty(storage, 'shared', { value: true });
    const removed: string[] = [];
    const remove = storage.remove.bind(storage);
    storage.remove = async (slot) => {
      removed.push(slot);
      return remove(slot);
    };

    const spentKey = await storage.create();
    await storage.set(APP_SLOT, {
      identity: spentKey,
      chain: await appDelegation(spentKey, -1_000),
    });

    const harnessed = harness({ storage });
    await harnessed.request();

    // Observed as a removal rather than by reading the slot afterwards: the mint
    // writes to the same slot, so the state after the fact is identical whether
    // the spent record was removed or overwritten.
    //
    // Only the state is meant to outlive a delegation, and it records who is
    // signed in by itself, so a spent key and chain go on the read that declines
    // them rather than sitting there until a sign-out.
    expect(removed).toEqual([APP_SLOT]);
  });

  it('never removes a spent credential before it holds the lock', async () => {
    const events: string[] = [];
    vi.stubGlobal('navigator', {
      locks: {
        request: async (_name: string, run: () => Promise<unknown>) => {
          events.push('lock');
          return run();
        },
      },
    });

    const storage = new MemoryCredentialStorage();
    Object.defineProperty(storage, 'shared', { value: true });
    const remove = storage.remove.bind(storage);
    storage.remove = async (slot) => {
      events.push('remove');
      return remove(slot);
    };

    const spentKey = await storage.create();
    await storage.set(APP_SLOT, {
      identity: spentKey,
      chain: await appDelegation(spentKey, -1_000),
    });

    // `refresh()` reads before taking the lock, which is what makes the ordering
    // the thing to assert. The store reaches every tab of the origin, so a
    // lock-free read that removed what it declined could delete a credential
    // another tab minted between the read and the removal — and that is the
    // ordinary case, since a delegation running out is exactly when several tabs
    // wake and one of them mints.
    const { identity } = harness({ storage });
    await identity.refresh();

    expect(events).toEqual(['lock', 'remove']);
  });

  it('keeps a credential it declines only for being close to expiry', async () => {
    const storage = new MemoryCredentialStorage();
    Object.defineProperty(storage, 'shared', { value: true });
    const removed: string[] = [];
    const remove = storage.remove.bind(storage);
    storage.remove = async (slot) => {
      removed.push(slot);
      return remove(slot);
    };

    const nearlyKey = await storage.create();
    await storage.set(APP_SLOT, {
      identity: nearlyKey,
      chain: await appDelegation(nearlyKey, 5_000),
    });

    const harnessed = harness({ storage });
    await harnessed.request();

    // Not expired, so removal is not what happens to it: it is replaced by the
    // mint that follows. Evicting on the threshold rather than on expiry would
    // empty the slot every time a tab woke near a rotation.
    expect(removed).toEqual([]);
  });

  it('reads, writes and locks on the slot it was given', async () => {
    const held: string[] = [];
    const request = vi.fn(async (name: string, run: () => Promise<unknown>) => {
      held.push(name);
      return run();
    });
    vi.stubGlobal('navigator', { locks: { request } });

    const storage = new MemoryCredentialStorage();
    Object.defineProperty(storage, 'shared', { value: true });
    const harnessed = harness({ storage, slot: 'ns:app' });
    await harnessed.request();

    // The client names every slot from one namespace, so reaching for the bare
    // constant here would put the credential where the client never looks: a
    // namespaced client would mint again on every load, and its sign-out would
    // clear a slot nothing was using.
    expect(await storage.get('ns:app')).not.toBeNull();
    expect(await storage.get(APP_SLOT)).toBeNull();
    expect(held).toEqual(['ns:app']);
  });

  it('takes no lock where no other tab can read the store', async () => {
    const request = vi.fn();
    vi.stubGlobal('navigator', { locks: { request } });

    const storage = new MemoryCredentialStorage(); // shared === false
    const harnessed = harness({ storage });
    await harnessed.request();

    expect(request).not.toHaveBeenCalled();
  });

  it('mints while holding the lock where another tab can read the store', async () => {
    const held: string[] = [];
    const request = vi.fn(async (name: string, run: () => Promise<unknown>) => {
      held.push(name);
      return run();
    });
    vi.stubGlobal('navigator', { locks: { request } });

    const storage = new MemoryCredentialStorage();
    Object.defineProperty(storage, 'shared', { value: true });
    const harnessed = harness({ storage });
    await harnessed.request();

    expect(held).toEqual([APP_SLOT]);
  });

  it('does not let a glance at a healthy tab cancel its own rotation', async () => {
    const { identity, request, mint } = harness();
    await request(); // the delegation has now signed something

    // A foreground event on a tab whose delegation is fine. Re-adopting it here
    // would clear the flag the scheduled refresh checks.
    await identity.refresh();

    await vi.advanceTimersByTimeAsync(TTL - 15_000);

    expect(mint).toHaveBeenCalledTimes(2); // the scheduled rotation still fired
  });

  it('uses a credential it minted even when it cannot be stored', async () => {
    const storage = new MemoryCredentialStorage();
    storage.set = () => Promise.reject(new Error('quota exceeded'));
    const { request } = harness({ storage });

    // The request is waiting on this; a write that failed is not its problem.
    await expect(request()).resolves.toBeDefined();
  });

  it('stops scheduling once disposed', async () => {
    const { mint, identity, request } = harness();
    await request();
    identity.dispose();

    await vi.advanceTimersByTimeAsync(TTL);

    expect(mint).toHaveBeenCalledTimes(1);
  });
});
