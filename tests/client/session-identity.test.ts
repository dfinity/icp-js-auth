import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SessionGoneError } from '../../src/client/app-delegation-source.ts';
import { SessionIdentity } from '../../src/client/session-identity.ts';

const MINUTE = 60_000;
const TTL = 5 * MINUTE;

const accountKey = Ed25519KeyIdentity.generate();
const accountDer = accountKey.getPublicKey().toDer();

/** A chain rooted at the account key, as the canister mints them. */
async function appDelegation(lifetimeMs = TTL): Promise<DelegationChain> {
  const chain = await DelegationChain.create(
    accountKey,
    Ed25519KeyIdentity.generate().getPublicKey(),
    new Date(Date.now() + lifetimeMs),
  );
  return DelegationChain.fromDelegations(chain.delegations, accountDer);
}

function harness(
  options: { lifetimeMs?: number; sessionMs?: number; onSessionGone?: () => void } = {},
) {
  const mint = vi.fn(async () => appDelegation(options.lifetimeMs ?? TTL));
  const onSessionGone = options.onSessionGone ?? vi.fn();
  const identity = new SessionIdentity({
    appKey: Ed25519KeyIdentity.generate(),
    accountKey: accountDer,
    sessionExpiresAtMs: Date.now() + (options.sessionMs ?? 30 * MINUTE),
    source: { mint },
    onSessionGone,
  });
  const request = () =>
    identity.transformRequest({ body: { arg: new Uint8Array() } } as never) as Promise<unknown>;
  return { identity, mint, onSessionGone, request };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

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

    await expect(request()).rejects.toThrow('rooted at another account');
  });

  it('stops scheduling once disposed', async () => {
    const { mint, identity, request } = harness();
    await request();
    identity.dispose();

    await vi.advanceTimersByTimeAsync(TTL);

    expect(mint).toHaveBeenCalledTimes(1);
  });
});
