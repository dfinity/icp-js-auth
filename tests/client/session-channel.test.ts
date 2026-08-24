import { afterEach, describe, expect, it, vi } from 'vitest';

import { openSessionChannel, type SessionMessage } from '../../src/client/session-channel.ts';

const open: (() => void)[] = [];
afterEach(() => {
  for (const close of open.splice(0)) close();
  vi.unstubAllGlobals();
});

function channel(name: string) {
  const received: SessionMessage[] = [];
  const handle = openSessionChannel(name, (message) => received.push(message));
  if (handle) open.push(handle.close);
  return { handle, received };
}

/** A channel delivers asynchronously, so let the queue drain. */
const delivered = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('openSessionChannel', () => {
  it('carries a message to another tab of the same origin', async () => {
    const a = channel('ic-delegation');
    const b = channel('ic-delegation');

    a.handle?.post({ kind: 'ask' });
    await delivered();

    expect(b.received).toEqual([{ kind: 'ask' }]);
  });

  it('does not deliver a tab its own message', async () => {
    const a = channel('ic-delegation');

    a.handle?.post({ kind: 'ask' });
    await delivered();

    expect(a.received).toEqual([]);
  });

  it('keeps clients on different slots apart', async () => {
    const a = channel('ic-delegation');
    const other = channel('other-slot');

    a.handle?.post({ kind: 'ask' });
    await delivered();

    expect(other.received).toEqual([]);
  });

  it('carries a key as a handle that signs and cannot be exported', async () => {
    const { ECDSAKeyIdentity } = await import('@icp-sdk/core/identity');
    const identity = await ECDSAKeyIdentity.generate({ extractable: false });
    const a = channel('ic-delegation');
    const b = channel('ic-delegation');

    a.handle?.post({ kind: 'offer', keyPair: identity.getKeyPair() });
    await delivered();

    const offer = b.received[0];
    expect(offer?.kind).toBe('offer');
    if (offer?.kind !== 'offer') throw new Error('expected an offer');
    expect(offer.keyPair.privateKey.extractable).toBe(false);
    const revived = await ECDSAKeyIdentity.fromKeyPair(offer.keyPair);
    await expect(revived.sign(new Uint8Array([1]))).resolves.toBeDefined();
  });

  it('ignores anything that is not one of its messages', async () => {
    const a = channel('ic-delegation');
    const b = channel('ic-delegation');

    (a.handle as unknown as { post(m: unknown): void }).post({ kind: 'something-else' });
    await delivered();

    expect(b.received).toEqual([]);
  });

  it('delivers nothing once closed', async () => {
    const a = channel('ic-delegation');
    const b = channel('ic-delegation');
    b.handle?.close();

    a.handle?.post({ kind: 'ask' });
    await delivered();

    expect(b.received).toEqual([]);
  });

  it('returns nothing where the environment has no channel', () => {
    vi.stubGlobal('BroadcastChannel', undefined);
    expect(openSessionChannel('ic-delegation', () => undefined)).toBeUndefined();
  });
});
