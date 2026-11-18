import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  isInstalledApp,
  isSafariInstalledApp,
  type PwaNotificationService,
  PwaNotifications,
  prepareSameDeviceLinkUrl,
  sealSubscription,
  subscribeDevice,
} from '../../src/client/pwa-notifications.ts';
import { SessionGoneError } from '../../src/client/session/app-delegation-source.ts';

/** The private constructor, which is how `notification-consent.test.ts` reaches its own. */
const over = (service: unknown): PwaNotifications =>
  new (PwaNotifications as unknown as new (service: unknown) => PwaNotifications)(service);

const KEYS = {
  vapid_public_key: new Uint8Array([4, 1, 2, 3]),
  transport_public_key: new Uint8Array([4, 9, 9, 9]),
};

function fakeService(answers: Partial<PwaNotificationService>): PwaNotificationService {
  return {
    app_prepare_pwa_webpush_subscription: vi.fn(async () => ({ Ok: KEYS })),
    app_set_pwa_webpush_subscription: vi.fn(async () => ({ Ok: null })),
    app_get_pwa_notification: vi.fn(async () => ({ Ok: { notification: [] } })),
    app_remove_pwa_notification: vi.fn(async () => ({ Ok: {} })),
    ...answers,
  } as PwaNotificationService;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('isInstalledApp', () => {
  it('reads the standalone display mode', () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query === '(display-mode: standalone)',
    }));

    expect(isInstalledApp()).toBe(true);
  });

  it('reads navigator.standalone, which iOS reports a Home Screen app through', () => {
    vi.stubGlobal('matchMedia', () => ({ matches: false }));
    vi.stubGlobal('navigator', { standalone: true });

    expect(isInstalledApp()).toBe(true);
  });

  it('answers no in a browser tab', () => {
    vi.stubGlobal('matchMedia', () => ({ matches: false }));

    expect(isInstalledApp()).toBe(false);
  });
});

describe('isSafariInstalledApp', () => {
  it('answers no in an installed app of a browser without navigator.standalone', () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query === '(display-mode: standalone)',
    }));
    vi.stubGlobal('navigator', {});

    expect(isSafariInstalledApp()).toBe(false);
  });

  it('answers no in a Safari tab', () => {
    vi.stubGlobal('matchMedia', () => ({ matches: false }));
    vi.stubGlobal('navigator', { standalone: false });

    expect(isSafariInstalledApp()).toBe(false);
  });

  it('answers yes in a Safari Home Screen app', () => {
    vi.stubGlobal('matchMedia', () => ({ matches: false }));
    vi.stubGlobal('navigator', { standalone: true });

    expect(isSafariInstalledApp()).toBe(true);
  });
});

describe('PwaNotifications', () => {
  it('asks again while Internet Identity answers Pending', async () => {
    vi.useFakeTimers();
    const prepare = vi
      .fn()
      .mockResolvedValueOnce({ Pending: null })
      .mockResolvedValueOnce({ Ok: KEYS });
    const preparing = over(
      fakeService({ app_prepare_pwa_webpush_subscription: prepare }),
    ).prepare();

    await vi.advanceTimersByTimeAsync(1_000);

    await expect(preparing).resolves.toEqual({
      vapidPublicKey: KEYS.vapid_public_key,
      transportPublicKey: KEYS.transport_public_key,
    });
    expect(prepare).toHaveBeenCalledTimes(2);
  });

  it('turns a missing session into SessionGoneError', async () => {
    const inbox = over(
      fakeService({
        app_get_pwa_notification: vi.fn(async () => ({ Err: { NoSuchSession: null } })),
      }),
    );

    await expect(inbox.get(BigInt(1))).rejects.toThrow(SessionGoneError);
  });

  it('removes this device with no subscription', async () => {
    const set = vi.fn(async () => ({ Ok: null }));

    await over(fakeService({ app_set_pwa_webpush_subscription: set })).set(null);

    expect(set).toHaveBeenCalledWith({ subscription: [] });
  });

  it('removes an entry with why it was not shown', async () => {
    const remove = vi.fn(async () => ({ Ok: {} }));

    await over(fakeService({ app_remove_pwa_notification: remove })).remove(BigInt(7), {
      PayloadRejected: null,
    });

    expect(remove).toHaveBeenCalledWith({
      inbox_notification_id: BigInt(7),
      not_shown: [{ PayloadRejected: null }],
    });
  });
});

/** A push subscription with real keys, so sealing can be checked end to end. */
async function fakeSubscription(endpoint: string, vapid: Uint8Array) {
  const subscriber = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ]);
  const p256dh = await crypto.subtle.exportKey('raw', subscriber.publicKey);
  const auth = crypto.getRandomValues(new Uint8Array(16)).buffer;
  return {
    endpoint,
    options: { applicationServerKey: vapid.buffer },
    getKey: (name: string) => (name === 'p256dh' ? p256dh : auth),
    unsubscribe: vi.fn(async () => true),
    auth: new Uint8Array(auth),
  };
}

describe('sealSubscription', () => {
  it('seals auth so the holder of the transport key opens it, as the canister does', async () => {
    const transport = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits'],
    );
    const transportPublicKey = new Uint8Array(
      await crypto.subtle.exportKey('raw', transport.publicKey),
    );
    const subscription = await fakeSubscription('https://push.example/1', new Uint8Array());

    const sealed = await sealSubscription(
      subscription as unknown as PushSubscription,
      transportPublicKey,
    );

    const browserKey = await crypto.subtle.importKey(
      'raw',
      sealed.transport_key as Uint8Array<ArrayBuffer>,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    );
    const shared = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: browserKey },
      transport.privateKey,
      256,
    );
    const hkdf = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
    const info = (label: string) =>
      new Uint8Array([
        ...new TextEncoder().encode('II webpush transport\0'),
        ...transportPublicKey,
        ...sealed.transport_key,
        ...new TextEncoder().encode(label),
      ]);
    const derive = (label: string, bits: number) =>
      crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new ArrayBuffer(0), info: info(label) },
        hkdf,
        bits,
      );
    const key = await crypto.subtle.importKey('raw', await derive('key\0', 128), 'AES-GCM', false, [
      'decrypt',
    ]);
    const opened = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: await derive('iv\0', 96) },
      key,
      sealed.sealed_auth as Uint8Array<ArrayBuffer>,
    );

    expect(new Uint8Array(opened)).toEqual(subscription.auth);
    expect(sealed.endpoint).toBe('https://push.example/1');
    expect(sealed.sealed_auth).toHaveLength(32);
  });
});

describe('subscribeDevice', () => {
  async function setUp(setAnswers: unknown[]) {
    const transport = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits'],
    );
    const transportPublicKey = new Uint8Array(
      await crypto.subtle.exportKey('raw', transport.publicKey),
    );
    const keys = {
      vapid_public_key: KEYS.vapid_public_key,
      transport_public_key: transportPublicKey,
    };
    const set = vi.fn();
    for (const answer of setAnswers) set.mockResolvedValueOnce(answer);
    const inbox = over(
      fakeService({
        app_prepare_pwa_webpush_subscription: vi.fn(async () => ({ Ok: keys })),
        app_set_pwa_webpush_subscription: set,
      }),
    );
    const first = await fakeSubscription('https://push.example/1', KEYS.vapid_public_key);
    const second = await fakeSubscription('https://push.example/2', KEYS.vapid_public_key);
    const subscribe = vi.fn().mockResolvedValueOnce(first).mockResolvedValueOnce(second);
    const registration = {
      pushManager: { getSubscription: vi.fn(async () => null), subscribe },
    } as unknown as ServiceWorkerRegistration;
    return { inbox, registration, set, subscribe, first };
  }

  it('subscribes with the VAPID key and registers the sealed subscription', async () => {
    const { inbox, registration, set, subscribe } = await setUp([{ Ok: null }]);

    await subscribeDevice(inbox, registration);

    expect(subscribe).toHaveBeenCalledWith(expect.objectContaining({ userVisibleOnly: true }));
    expect(set).toHaveBeenCalledTimes(1);
    expect(set.mock.calls[0][0].subscription[0].endpoint).toBe('https://push.example/1');
  });

  it('reuses the push subscription the service worker already holds', async () => {
    const { inbox, registration, set, subscribe, first } = await setUp([{ Ok: null }]);
    vi.mocked(registration.pushManager.getSubscription).mockResolvedValueOnce(
      first as unknown as PushSubscription,
    );

    await subscribeDevice(inbox, registration);

    expect(subscribe).not.toHaveBeenCalled();
    expect(set.mock.calls[0][0].subscription[0].endpoint).toBe('https://push.example/1');
  });

  it('replaces a push subscription bound to another key', async () => {
    const { inbox, registration, set, subscribe } = await setUp([{ Ok: null }]);
    const other = await fakeSubscription(
      'https://push.example/other',
      new Uint8Array([4, 7, 7, 7]),
    );
    vi.mocked(registration.pushManager.getSubscription).mockResolvedValueOnce(
      other as unknown as PushSubscription,
    );

    await subscribeDevice(inbox, registration);

    expect(other.unsubscribe).toHaveBeenCalled();
    expect(subscribe).toHaveBeenCalledWith(expect.objectContaining({ userVisibleOnly: true }));
    expect(set.mock.calls[0][0].subscription[0].endpoint).toBe('https://push.example/1');
  });

  it('moves to a fresh endpoint once where the endpoint is held with other keys', async () => {
    const { inbox, registration, set, first } = await setUp([
      { Err: { EndpointInUse: null } },
      { Ok: null },
    ]);

    await subscribeDevice(inbox, registration);

    expect(first.unsubscribe).toHaveBeenCalled();
    expect(set).toHaveBeenCalledTimes(2);
    expect(set.mock.calls[1][0].subscription[0].endpoint).toBe('https://push.example/2');
  });

  it('retries no more than once', async () => {
    const { inbox, registration } = await setUp([
      { Err: { EndpointInUse: null } },
      { Err: { EndpointInUse: null } },
    ]);

    await expect(subscribeDevice(inbox, registration)).rejects.toThrow(
      'This push endpoint is registered with other keys',
    );
  });
});

describe('same-device link', () => {
  it.each([
    [{ Linked: null }, 'linked'],
    [{ OtherPathMayDeliver: null }, 'other-path-may-deliver'],
    [{ NoOtherPath: null }, 'no-other-path'],
  ])('reads %o as %s', async (answer, status) => {
    const inbox = over(
      fakeService({ app_get_same_device_link_status: vi.fn(async () => ({ Ok: answer })) }),
    );

    await expect(inbox.sameDeviceLinkStatus()).resolves.toBe(status);
  });

  it('registers the public half of the key whose private half the URL carries', async () => {
    const prepare = vi.fn(async (_: { link_public_key: Uint8Array }) => ({ Ok: null }));
    const inbox = over(fakeService({ app_prepare_same_device_link: prepare }));

    const url = new URL(await prepareSameDeviceLinkUrl(inbox, 'https://id.example'));

    expect(url.origin + url.pathname).toBe('https://id.example/ios-installed-app');
    expect(url.search).toBe('');
    const key = new URLSearchParams(url.hash.slice(1)).get('key') ?? '';
    const bytes = Uint8Array.from(
      atob(key.replace(/-/g, '+').replace(/_/g, '/').padEnd(128, '=')),
      (char) => char.charCodeAt(0),
    );
    expect(bytes).toHaveLength(96);
    const coordinate = (at: number) =>
      btoa(String.fromCharCode(...bytes.subarray(at * 32, (at + 1) * 32)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: 'P-256', d: coordinate(0), x: coordinate(1), y: coordinate(2) },
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    );
    const registered = await crypto.subtle.importKey(
      'spki',
      prepare.mock.calls[0][0].link_public_key as Uint8Array<ArrayBuffer>,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    const message = new TextEncoder().encode('claim');
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      message,
    );

    await expect(
      crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, registered, signature, message),
    ).resolves.toBe(true);
  });

  it('hands out no URL where Internet Identity refuses the key', async () => {
    const inbox = over(
      fakeService({
        app_prepare_same_device_link: vi.fn(async () => ({ Err: { NoSuchSession: null } })),
      }),
    );

    await expect(prepareSameDeviceLinkUrl(inbox, 'https://id.example')).rejects.toThrow(
      SessionGoneError,
    );
  });
});
