import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from 'vitest';
import { IdbStorage } from '../../src/client/storage.ts';
import { CHANNEL, PROTOCOL_VERSION } from '../../src/shared-session/protocol.ts';
import { serveSharedSession } from '../../src/shared-session/serve.ts';

// jsdom serves the tests from this origin, so it doubles as the hub's own origin.
const HUB_ORIGIN = 'http://localhost:3000';
const DERIVATION_ORIGIN = 'https://example.com';
const CLIENT_ORIGIN = 'https://a.example.com';
const CANISTER_ID = 'rdmx6-jaaaa-aaaaa-aaadq-cai';

let stop: (() => void) | undefined;
let counter = 0;

const testStorage = () => {
  counter += 1;
  return new IdbStorage({ dbName: `serve-db-${counter}`, storeName: `serve-store-${counter}` });
};

/** Stands in for the client window the hub replies to. */
function fakeClient(): { postMessage: Mock } {
  return { postMessage: vi.fn() };
}

function request(
  client: { postMessage: Mock },
  overrides: Record<string, unknown> = {},
  origin = CLIENT_ORIGIN,
) {
  const event = new MessageEvent('message', {
    origin,
    data: {
      v: PROTOCOL_VERSION,
      type: CHANNEL,
      id: 1,
      op: 'get',
      key: 'identity',
      ...overrides,
    },
  });
  // `source` is a prototype accessor, so it can only be supplied this way.
  Object.defineProperty(event, 'source', { value: client });
  window.dispatchEvent(event);
}

/** Resolves once the hub has answered, which it does asynchronously. */
async function reply(client: { postMessage: Mock }) {
  await vi.waitFor(() => expect(client.postMessage).toHaveBeenCalled());
  return client.postMessage.mock.calls[0][0] as Record<string, unknown>;
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  stop?.();
  stop = undefined;
});

describe('serveSharedSession', () => {
  it('serves an origin listed in the alternative origins record', async () => {
    const storage = testStorage();
    await storage.set('identity', 'stored-key');
    stop = serveSharedSession({
      derivationOrigin: DERIVATION_ORIGIN,
      storage,
      allowedOrigins: async () => [CLIENT_ORIGIN],
    });

    const client = fakeClient();
    request(client);

    expect(await reply(client)).toEqual({
      v: PROTOCOL_VERSION,
      type: CHANNEL,
      id: 1,
      result: 'stored-key',
    });
    expect(client.postMessage).toHaveBeenCalledWith(expect.anything(), CLIENT_ORIGIN);
  });

  it('round-trips set, get and remove', async () => {
    const storage = testStorage();
    stop = serveSharedSession({
      derivationOrigin: DERIVATION_ORIGIN,
      storage,
      allowedOrigins: async () => [CLIENT_ORIGIN],
    });

    const writer = fakeClient();
    request(writer, { op: 'set', value: 'written' });
    await reply(writer);
    expect(await storage.get('identity')).toBe('written');

    const remover = fakeClient();
    request(remover, { op: 'remove', id: 2 });
    await reply(remover);
    expect(await storage.get('identity')).toBeNull();
  });

  it('serves the derivation origin, which its own record does not list', async () => {
    stop = serveSharedSession({
      derivationOrigin: DERIVATION_ORIGIN,
      storage: testStorage(),
      allowedOrigins: async () => [],
    });

    const client = fakeClient();
    request(client, {}, DERIVATION_ORIGIN);

    expect(await reply(client)).not.toHaveProperty('error');
  });

  it('denies an origin the record does not list', async () => {
    stop = serveSharedSession({
      derivationOrigin: DERIVATION_ORIGIN,
      storage: testStorage(),
      allowedOrigins: async () => [CLIENT_ORIGIN],
    });

    const client = fakeClient();
    request(client, {}, 'https://evil.example.com');

    expect(await reply(client)).toMatchObject({ error: 'denied' });
  });

  it.each([
    ['a path', `${CLIENT_ORIGIN}/callback`],
    ['a trailing slash', `${CLIENT_ORIGIN}/`],
    ['credentials', 'https://user:pass@a.example.com'],
    ['plain http', 'http://a.example.com'],
    ['a non-string entry', 42 as unknown as string],
  ])('ignores a record entry carrying %s', async (_label, entry) => {
    stop = serveSharedSession({
      derivationOrigin: DERIVATION_ORIGIN,
      storage: testStorage(),
      allowedOrigins: async () => [entry],
    });

    const client = fakeClient();
    request(client);

    expect(await reply(client)).toMatchObject({ error: 'denied' });
  });

  it('denies a client speaking a different protocol version', async () => {
    stop = serveSharedSession({
      derivationOrigin: DERIVATION_ORIGIN,
      storage: testStorage(),
      allowedOrigins: async () => [CLIENT_ORIGIN],
    });

    const client = fakeClient();
    request(client, { v: PROTOCOL_VERSION + 1 });

    expect((await reply(client)).error).toContain('unsupported protocol version');
  });

  it('denies an unknown operation', async () => {
    stop = serveSharedSession({
      derivationOrigin: DERIVATION_ORIGIN,
      storage: testStorage(),
      allowedOrigins: async () => [CLIENT_ORIGIN],
    });

    const client = fakeClient();
    request(client, { op: 'clear' });

    expect(await reply(client)).toMatchObject({ error: 'denied' });
  });

  it('ignores a message without an id, which is not a request', async () => {
    stop = serveSharedSession({
      derivationOrigin: DERIVATION_ORIGIN,
      storage: testStorage(),
      allowedOrigins: async () => [CLIENT_ORIGIN],
    });

    const client = fakeClient();
    request(client, { id: undefined, ready: true });

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(client.postMessage).not.toHaveBeenCalled();
  });

  it('fails closed when discovery fails, and retries on the next request', async () => {
    const allowedOrigins = vi
      .fn<() => Promise<string[]>>()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValue([CLIENT_ORIGIN]);
    stop = serveSharedSession({
      derivationOrigin: DERIVATION_ORIGIN,
      storage: testStorage(),
      allowedOrigins,
    });

    const denied = fakeClient();
    request(denied);
    expect(await reply(denied)).toMatchObject({ error: 'denied' });

    const allowed = fakeClient();
    request(allowed, { id: 2 });
    expect(await reply(allowed)).not.toHaveProperty('error');
    expect(allowedOrigins).toHaveBeenCalledTimes(2);
  });

  it('announces itself to the embedder and stops serving when disposed', async () => {
    const announce = vi.spyOn(window.parent, 'postMessage');
    const dispose = serveSharedSession({
      derivationOrigin: DERIVATION_ORIGIN,
      storage: testStorage(),
      allowedOrigins: async () => [CLIENT_ORIGIN],
    });

    expect(announce).toHaveBeenCalledWith({ v: PROTOCOL_VERSION, type: CHANNEL, ready: true }, '*');

    dispose();
    const client = fakeClient();
    request(client);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(client.postMessage).not.toHaveBeenCalled();
  });

  it('rejects a canister id that is not a principal', () => {
    expect(() =>
      serveSharedSession({
        derivationOrigin: DERIVATION_ORIGIN,
        canisterId: 'not-a-principal',
        storage: testStorage(),
      }),
    ).toThrow('not a valid principal');
  });
});

describe('serveSharedSession allow-list discovery', () => {
  const record = (alternativeOrigins: unknown) =>
    vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ alternativeOrigins }),
    });

  it('reads the record through the gateway when a canister id is given', async () => {
    const fetchMock = record([CLIENT_ORIGIN]);
    vi.stubGlobal('fetch', fetchMock);
    stop = serveSharedSession({
      derivationOrigin: DERIVATION_ORIGIN,
      canisterId: CANISTER_ID,
      storage: testStorage(),
    });

    const client = fakeClient();
    request(client);
    await reply(client);

    expect(fetchMock).toHaveBeenCalledWith(
      `https://${CANISTER_ID}.icp0.io/.well-known/ii-alternative-origins`,
      expect.objectContaining({ redirect: 'error', credentials: 'omit' }),
    );
  });

  it('reads the record same-origin when it owns the derivation origin', async () => {
    const fetchMock = record([CLIENT_ORIGIN]);
    vi.stubGlobal('fetch', fetchMock);
    stop = serveSharedSession({ derivationOrigin: HUB_ORIGIN, storage: testStorage() });

    const client = fakeClient();
    request(client);
    await reply(client);

    expect(fetchMock).toHaveBeenCalledWith(
      '/.well-known/ii-alternative-origins',
      expect.anything(),
    );
  });

  it('warns when reading a remote record without certification', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.stubGlobal('fetch', record([CLIENT_ORIGIN]));
    stop = serveSharedSession({ derivationOrigin: DERIVATION_ORIGIN, storage: testStorage() });

    const client = fakeClient();
    request(client);
    await reply(client);

    expect(warn.mock.calls[0][0]).toContain('without certification');
  });

  it('denies everyone when the record lists more origins than II accepts', async () => {
    vi.stubGlobal(
      'fetch',
      record(Array.from({ length: 11 }, (_, i) => `https://a${i}.example.com`)),
    );
    stop = serveSharedSession({
      derivationOrigin: DERIVATION_ORIGIN,
      canisterId: CANISTER_ID,
      storage: testStorage(),
    });

    const client = fakeClient();
    request(client);
    expect(await reply(client)).toMatchObject({ error: 'denied' });
  });

  it('denies everyone when the record is malformed', async () => {
    vi.stubGlobal('fetch', record('https://a.example.com'));
    stop = serveSharedSession({
      derivationOrigin: DERIVATION_ORIGIN,
      canisterId: CANISTER_ID,
      storage: testStorage(),
    });

    const client = fakeClient();
    request(client);
    expect(await reply(client)).toMatchObject({ error: 'denied' });
  });
});
