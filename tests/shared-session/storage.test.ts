import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CHANNEL, PROTOCOL_VERSION } from '../../src/shared-session/protocol.ts';
import { SharedSessionStorage } from '../../src/shared-session/storage.ts';

const HUB_URL = 'https://auth.example.com/hub.html';
const HUB_ORIGIN = 'https://auth.example.com';
const DERIVATION_ORIGIN = 'https://example.com';

const testStorage = (timeout = 500) =>
  new SharedSessionStorage({
    hub: { url: HUB_URL, timeout },
    derivationOrigin: DERIVATION_ORIGIN,
  });

/**
 * Stands in for the hub page. jsdom leaves an iframe on `about:blank` because
 * subresources are not loaded, so its window is a usable postMessage target.
 */
async function hub() {
  const frame = await vi.waitFor(() => {
    const found = document.querySelector('iframe');
    expect(found).not.toBeNull();
    return found as HTMLIFrameElement;
  });
  const window = frame.contentWindow;
  if (window === null) throw new Error('iframe has no content window');
  const post = vi.spyOn(window, 'postMessage');

  const send = (data: unknown, source: unknown = window) => {
    const event = new MessageEvent('message', { origin: HUB_ORIGIN, data });
    // `source` is a prototype accessor, so it can only be supplied this way.
    Object.defineProperty(event, 'source', { value: source });
    globalThis.dispatchEvent(event);
  };

  return {
    frame,
    post,
    send,
    ready: (v = PROTOCOL_VERSION) => send({ v, type: CHANNEL, ready: true }),
    /** Answers the client's nth request, defaulting to the first. */
    answer: async (body: Record<string, unknown>, nth = 0) => {
      await vi.waitFor(() => expect(post.mock.calls.length).toBeGreaterThan(nth));
      const request = post.mock.calls[nth][0] as { id: number };
      send({ v: PROTOCOL_VERSION, type: CHANNEL, id: request.id, ...body });
      return request;
    },
  };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  for (const frame of document.querySelectorAll('iframe')) frame.remove();
});

describe('SharedSessionStorage', () => {
  it.each([
    ['a relative url', '/hub.html', 'must be an absolute URL'],
    ['plain http', 'http://auth.example.com/hub.html', 'must be served over https'],
  ])('rejects %s for the hub', (_label, url, message) => {
    expect(
      () => new SharedSessionStorage({ hub: { url }, derivationOrigin: DERIVATION_ORIGIN }),
    ).toThrow(message);
  });

  it('accepts a loopback hub for local development', () => {
    expect(
      () =>
        new SharedSessionStorage({
          hub: { url: 'http://localhost:5174/hub.html' },
          derivationOrigin: 'http://localhost:5173',
        }),
    ).not.toThrow();
  });

  it('reads through the hub once it announces itself', async () => {
    const storage = testStorage();
    const pending = storage.get('identity');
    const { post, ready, answer } = await hub();

    ready();
    const request = await answer({ result: 'stored-key' });

    expect(request).toMatchObject({
      v: PROTOCOL_VERSION,
      type: CHANNEL,
      op: 'get',
      key: 'identity',
      derivationOrigin: DERIVATION_ORIGIN,
    });
    expect(post).toHaveBeenCalledWith(expect.anything(), HUB_ORIGIN);
    expect(await pending).toBe('stored-key');
  });

  it('writes and removes through the hub', async () => {
    const storage = testStorage();
    const written = storage.set('identity', 'written');
    const { ready, answer } = await hub();
    ready();

    expect(await answer({ result: null })).toMatchObject({ op: 'set', value: 'written' });
    await expect(written).resolves.toBeUndefined();

    const removed = storage.remove('identity');
    expect(await answer({ result: null }, 1)).toMatchObject({ op: 'remove' });
    await expect(removed).resolves.toBeUndefined();
  });

  it('reports a missing value as null', async () => {
    const storage = testStorage();
    const pending = storage.get('identity');
    const { ready, answer } = await hub();

    ready();
    await answer({ result: null });

    expect(await pending).toBeNull();
  });

  it('reuses one hub connection across operations', async () => {
    const storage = testStorage();
    const first = storage.get('identity');
    const { ready, answer } = await hub();
    ready();
    await answer({ result: 'a' });
    expect(await first).toBe('a');

    const second = storage.get('delegation');
    await answer({ result: 'b' }, 1);
    expect(await second).toBe('b');

    expect(document.querySelectorAll('iframe')).toHaveLength(1);
  });

  it('surfaces an error reply from the hub', async () => {
    const storage = testStorage();
    const pending = storage.get('identity');
    const { ready, answer } = await hub();

    ready();
    await answer({ error: 'denied' });

    await expect(pending).rejects.toThrow('Shared session hub refused get: denied');
  });

  it('names the hub url when it never answers', async () => {
    const storage = testStorage(20);

    await expect(storage.get('identity')).rejects.toThrow(
      `Shared session hub at ${HUB_URL} did not respond within 20ms`,
    );
  });

  it('refuses a hub speaking a different protocol version', async () => {
    const storage = testStorage();
    const pending = storage.get('identity');
    const { ready } = await hub();

    ready(PROTOCOL_VERSION + 1);

    await expect(pending).rejects.toThrow(
      `speaks protocol version ${PROTOCOL_VERSION + 1}, this client speaks ${PROTOCOL_VERSION}`,
    );
  });

  it('ignores an announcement from another frame on the hub origin', async () => {
    const storage = testStorage(50);
    const pending = storage.get('identity');
    const { send } = await hub();

    send({ v: PROTOCOL_VERSION, type: CHANNEL, ready: true }, { name: 'another frame' });

    await expect(pending).rejects.toThrow('did not respond within');
  });

  it('removes the frame and retries after a failed connection', async () => {
    const storage = testStorage();
    const failed = storage.get('identity');
    const rejected = await hub();
    rejected.ready(PROTOCOL_VERSION + 1);

    await expect(failed).rejects.toThrow('speaks protocol version');
    expect(document.querySelectorAll('iframe')).toHaveLength(0);

    const retried = storage.get('identity');
    const retry = await hub();
    retry.ready();
    await retry.answer({ result: 'after-retry' });

    expect(await retried).toBe('after-retry');
    expect(document.querySelectorAll('iframe')).toHaveLength(1);
  });
});
