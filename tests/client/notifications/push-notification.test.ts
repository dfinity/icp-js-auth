import { Actor, AnonymousIdentity, HttpAgent, RejectError } from '@icp-sdk/core/agent';
import { Principal } from '@icp-sdk/core/principal';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthClient } from '../../../src/client/auth-client.ts';
import {
  fetchPushNotificationPayload,
  markPushNotificationOpened,
  type NotificationPushEvent,
  type PushNotificationScope,
  type PushNotificationSource,
} from '../../../src/client/notifications/push-notification.ts';
import {
  type PwaNotificationService,
  PwaNotifications,
} from '../../../src/client/notifications/pwa-notifications.ts';
import { SessionGoneError } from '../../../src/client/session/app-delegation-source.ts';

/** The private constructor, which is how `notification-consent.test.ts` reaches its own. */
/** The frontend the inbox is read for. */
const FRONTEND = 'https://app.example.com';

const over = (service: unknown): PwaNotifications =>
  new (
    PwaNotifications as unknown as new (
      service: unknown,
      frontendOrigin: string,
    ) => PwaNotifications
  )(service, FRONTEND);

function fakeService(answers: Partial<PwaNotificationService>): PwaNotificationService {
  return {
    app_get_pwa_notification: vi.fn(async () => ({ Ok: { notification: [], event: [] } })),
    app_remove_pwa_notification: vi.fn(async () => ({ Ok: {} })),
    ...answers,
  } as PwaNotificationService;
}

const GENERIC = {
  title: 'New notification',
  options: { tag: 'ii-notification' },
};

const SAFARI =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1';
const CHROME =
  'Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36';

function fakeScope(userAgent = CHROME) {
  const getNotifications = vi.fn(async (): Promise<{ tag: string; close(): void }[]> => []);
  return {
    scope: {
      location: { origin: 'https://app.example.com' },
      navigator: { userAgent },
      registration: { getNotifications },
    },
    getNotifications,
  };
}

const source = (inbox: () => Promise<PwaNotifications>) => ({
  inbox,
  identity: async () => new AnonymousIdentity(),
  agentOptions: undefined,
});

/** A push event that keeps what it was asked to wait for in `held`. */
const pushOf = (data: NotificationPushEvent['data']) => {
  const held: Promise<unknown>[] = [];
  return {
    data,
    waitUntil: (work: Promise<unknown>) => {
      held.push(work);
    },
    held,
  };
};

const push = (payload: unknown) => pushOf({ json: () => payload });

/** Fetches for `event`, with `settled()` waiting for everything the event was asked to wait for. */
const fetchAndSettle = async (
  from: PushNotificationSource,
  event: ReturnType<typeof pushOf>,
  scope: PushNotificationScope,
) => ({
  ...(await fetchPushNotificationPayload(from, event, scope)),
  settled: () => Promise.all(event.held).then(() => undefined),
});

const removeOf = (remove: ReturnType<typeof vi.fn>, id: number, notShown: unknown[] = []) =>
  expect(remove).toHaveBeenCalledWith({
    inbox_notification_id: BigInt(id),
    not_shown: notShown,
    frontend_origin: [FRONTEND],
  });

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('fetchPushNotification', () => {
  it('answers the generic notification for a payload it cannot read, with nothing to report', async () => {
    const remove = vi.fn(async () => ({ Ok: {} }));
    const inbox = vi.fn(async () => over(fakeService({ app_remove_pwa_notification: remove })));
    const { scope } = fakeScope();
    const unreadable = pushOf({
      json: () => {
        throw new SyntaxError('not JSON');
      },
    });

    const notification = await fetchAndSettle(source(inbox), unreadable, scope);
    await notification.settled();

    expect(notification).toMatchObject(GENERIC);
    expect(inbox).not.toHaveBeenCalled();
    expect(remove).not.toHaveBeenCalled();
  });

  it('rejects with SessionGoneError where no session is held', async () => {
    const { scope } = fakeScope();

    await expect(
      fetchAndSettle(
        source(async () => {
          throw new SessionGoneError();
        }),
        push({ inbox_notification_id: 3 }),
        scope,
      ),
    ).rejects.toThrow(SessionGoneError);
  });

  it('answers the generic notification where reading the session fails otherwise', async () => {
    const { scope } = fakeScope();

    const notification = await fetchAndSettle(
      source(async () => {
        throw new Error('storage unavailable');
      }),
      push({ inbox_notification_id: 3 }),
      scope,
    );

    expect(notification).toMatchObject(GENERIC);
    await expect(notification.settled()).resolves.toBeUndefined();
  });

  it('answers the generic notification where reading the entry fails, and clears it once settled', async () => {
    const remove = vi.fn(async () => ({ Ok: {} }));
    const { scope } = fakeScope();
    const inbox = over(
      fakeService({
        app_get_pwa_notification: vi.fn(async () => ({ Err: { InternalCanisterError: 'down' } })),
        app_remove_pwa_notification: remove,
      }),
    );

    const notification = await fetchAndSettle(
      source(async () => inbox),
      push({ inbox_notification_id: 3 }),
      scope,
    );

    expect(notification).toMatchObject(GENERIC);
    await notification.settled();
    removeOf(remove, 3);
  });

  it('closes an earlier generic notification before answering another, since iOS ignores the tag', async () => {
    const { scope, getNotifications } = fakeScope(SAFARI);
    const close = vi.fn();
    getNotifications.mockResolvedValue([{ tag: 'ii-notification', close }]);

    await fetchAndSettle(
      source(async () => over(fakeService({}))),
      push({ inbox_notification_id: 3 }),
      scope,
    );

    expect(close).toHaveBeenCalled();
  });

  it('answers the generic notification at the deadline, and clears the late entry once settled', async () => {
    vi.useFakeTimers();
    const { scope } = fakeScope();
    let release: (inbox: PwaNotifications) => void = () => undefined;
    const remove = vi.fn(async () => ({ Ok: {} }));

    const fetching = fetchAndSettle(
      source(
        () =>
          new Promise<PwaNotifications>((resolve) => {
            release = resolve;
          }),
      ),
      push({ inbox_notification_id: 3 }),
      scope,
    );
    await vi.advanceTimersByTimeAsync(8_000);
    const notification = await fetching;
    expect(notification).toMatchObject(GENERIC);

    const acknowledging = notification.settled();
    release(over(fakeService({ app_remove_pwa_notification: remove })));
    await acknowledging;
    removeOf(remove, 3);
  });

  it('fails the push with SessionGoneError where the session ends after the deadline', async () => {
    vi.useFakeTimers();
    const { scope } = fakeScope();
    let end: (error: Error) => void = () => undefined;

    const fetching = fetchAndSettle(
      source(
        () =>
          new Promise<PwaNotifications>((_, reject) => {
            end = reject;
          }),
      ),
      push({ inbox_notification_id: 3 }),
      scope,
    );
    await vi.advanceTimersByTimeAsync(8_000);
    const notification = await fetching;
    expect(notification).toMatchObject(GENERIC);

    const settling = notification.settled();
    end(new SessionGoneError());
    await expect(settling).rejects.toThrow(SessionGoneError);
  });

  it('clears an entry that is gone without a reason', async () => {
    const remove = vi.fn(async () => ({ Ok: {} }));
    const { scope } = fakeScope();

    const notification = await fetchAndSettle(
      source(async () => over(fakeService({ app_remove_pwa_notification: remove }))),
      push({ inbox_notification_id: 3 }),
      scope,
    );
    await notification.settled();

    expect(notification).toMatchObject(GENERIC);
    removeOf(remove, 3);
  });

  it('rejects with SessionGoneError where Internet Identity no longer holds the session', async () => {
    const { scope } = fakeScope();
    const inbox = over(
      fakeService({
        app_get_pwa_notification: vi.fn(async () => ({ Err: { NoSuchSession: null } })),
      }),
    );

    await expect(
      fetchAndSettle(
        source(async () => inbox),
        push({ inbox_notification_id: 3 }),
        scope,
      ),
    ).rejects.toThrow(SessionGoneError);
  });

  it('answers Internet Identity\'s probe as "All set", and clears it, which answers the probe', async () => {
    const remove = vi.fn(async () => ({ Ok: {} }));
    const { scope } = fakeScope();
    const inbox = over(
      fakeService({
        app_get_pwa_notification: vi.fn(async () => ({
          Ok: {
            notification: [] as [],
            event: [{ NotificationsOn: null }] as [{ NotificationsOn: null }],
          },
        })),
        app_remove_pwa_notification: remove,
      }),
    );

    const notification = await fetchAndSettle(
      source(async () => inbox),
      push({ inbox_notification_id: 4 }),
      scope,
    );

    expect(notification.title).toBe('All set');
    expect(notification.options).toEqual({
      body: 'Notifications will show up here.',
      tag: 'ii-notification:probe',
      renotify: true,
    });
    await notification.settled();
    removeOf(remove, 4);
  });

  describe("with the app's content", () => {
    const CANISTER = Principal.fromText('aaaaa-aa');

    function fakeApp(content: unknown[]) {
      const received = vi.fn(async () => undefined);
      vi.spyOn(HttpAgent, 'create').mockResolvedValue({} as HttpAgent);
      vi.spyOn(Actor, 'createActor').mockReturnValue({
        _internet_identity_notification_content: vi.fn(async () => content),
        _internet_identity_notification_received: received,
      } as never);
      const remove = vi.fn(async () => ({ Ok: {} }));
      const inbox = over(
        fakeService({
          app_get_pwa_notification: vi.fn(async () => ({
            Ok: {
              notification: [{ canister_id: CANISTER, id: BigInt(5) }] as [
                { canister_id: Principal; id: bigint },
              ],
              event: [] as [],
            },
          })),
          app_remove_pwa_notification: remove,
        }),
      );
      return { received, remove, inbox };
    }

    it('rejects with SessionGoneError where the session ends before the canister is called', async () => {
      const { inbox } = fakeApp([]);
      const { scope } = fakeScope();
      const gone = {
        ...source(async () => inbox),
        identity: async () => {
          throw new SessionGoneError();
        },
      };

      await expect(fetchAndSettle(gone, push({ inbox_notification_id: 3 }), scope)).rejects.toThrow(
        SessionGoneError,
      );
    });

    it("answers the app's notification with the tag and the data its canister sent", async () => {
      const { inbox } = fakeApp([{ title: 'Hi', body: 'There', url: ['/inbox'] }]);
      const { scope } = fakeScope();

      const notification = await fetchAndSettle(
        source(async () => inbox),
        push({ inbox_notification_id: 3 }),
        scope,
      );

      expect(notification.title).toBe('Hi');
      expect(notification.options).toEqual({
        body: 'There',
        tag: 'ii-notification:aaaaa-aa:5',
        data: { canisterId: 'aaaaa-aa', id: '5', url: 'https://app.example.com/inbox' },
        renotify: true,
      });
    });

    it('reports it received and clears the entry as it resolves, under waitUntil', async () => {
      const { inbox, received, remove } = fakeApp([{ title: 'Hi', body: 'There', url: [] }]);
      const { scope } = fakeScope();

      const notification = await fetchAndSettle(
        source(async () => inbox),
        push({ inbox_notification_id: 3 }),
        scope,
      );
      await notification.settled();

      expect(received).toHaveBeenCalledTimes(1);
      expect(received).toHaveBeenCalledWith(BigInt(5));
      expect(remove).toHaveBeenCalledTimes(1);
      removeOf(remove, 3);
    });

    it('closes a copy of the same notification already on screen before answering it, since iOS ignores the tag', async () => {
      const { inbox } = fakeApp([{ title: 'Hi', body: 'There', url: [] }]);
      const { scope, getNotifications } = fakeScope(SAFARI);
      const close = vi.fn();
      getNotifications.mockResolvedValue([{ tag: 'ii-notification:aaaaa-aa:5', close }]);

      const notification = await fetchAndSettle(
        source(async () => inbox),
        push({ inbox_notification_id: 3 }),
        scope,
      );

      expect(close).toHaveBeenCalled();
      expect(notification.options).not.toHaveProperty('renotify');
    });

    it('replaces a copy of the same notification in place where the tag is honoured, and renotifies', async () => {
      const { inbox } = fakeApp([{ title: 'Hi', body: 'There', url: [] }]);
      const { scope, getNotifications } = fakeScope(CHROME);

      const notification = await fetchAndSettle(
        source(async () => inbox),
        push({ inbox_notification_id: 3 }),
        scope,
      );

      expect(getNotifications).not.toHaveBeenCalled();
      expect(notification.options).toMatchObject({
        tag: 'ii-notification:aaaaa-aa:5',
        renotify: true,
      });
    });

    it('answers the generic notification, and clears the entry as rejected, where the canister rejects the call', async () => {
      const { inbox, remove } = fakeApp([]);
      const { scope } = fakeScope();
      vi.mocked(Actor.createActor).mockReturnValue({
        _internet_identity_notification_content: vi.fn(async () => {
          throw Object.create(RejectError.prototype);
        }),
      } as never);

      const notification = await fetchAndSettle(
        source(async () => inbox),
        push({ inbox_notification_id: 3 }),
        scope,
      );
      await notification.settled();

      expect(notification).toMatchObject(GENERIC);
      removeOf(remove, 3, [{ PayloadRejected: null }]);
    });

    it('closes a dismissed notification on screen, answers the generic one, and clears the entry without a reason', async () => {
      const { inbox, remove } = fakeApp([]);
      const { scope, getNotifications } = fakeScope();
      const close = vi.fn();
      getNotifications.mockResolvedValue([{ tag: 'ii-notification:aaaaa-aa:5', close }]);

      const notification = await fetchAndSettle(
        source(async () => inbox),
        push({ inbox_notification_id: 3 }),
        scope,
      );
      await notification.settled();

      expect(close).toHaveBeenCalled();
      expect(notification).toMatchObject(GENERIC);
      removeOf(remove, 3);
    });

    it('never shows an answer that arrives after the deadline, and clears it as unreachable', async () => {
      vi.useFakeTimers();
      const { inbox, received, remove } = fakeApp([{ title: 'Hi', body: 'There', url: [] }]);
      const { scope } = fakeScope();
      let release: () => void = () => undefined;

      const fetching = fetchAndSettle(
        source(
          () =>
            new Promise<PwaNotifications>((resolve) => {
              release = () => resolve(inbox);
            }),
        ),
        push({ inbox_notification_id: 3 }),
        scope,
      );
      await vi.advanceTimersByTimeAsync(8_000);
      const notification = await fetching;
      const acknowledging = notification.settled();
      release();
      await acknowledging;

      expect(notification).toMatchObject(GENERIC);
      expect(received).not.toHaveBeenCalled();
      removeOf(remove, 3, [{ PayloadUnreachable: null }]);
    });

    it('answers the generic notification, and clears the entry as unreachable, where the canister cannot be reached', async () => {
      const { inbox, remove } = fakeApp([]);
      const { scope } = fakeScope();
      vi.mocked(Actor.createActor).mockReturnValue({
        _internet_identity_notification_content: vi.fn(async () => {
          throw new Error('unreachable');
        }),
      } as never);

      const notification = await fetchAndSettle(
        source(async () => inbox),
        push({ inbox_notification_id: 3 }),
        scope,
      );
      await notification.settled();

      expect(notification).toMatchObject(GENERIC);
      removeOf(remove, 3, [{ PayloadUnreachable: null }]);
    });
  });
});

describe('fetchPushNotificationPayload and waitUntil', () => {
  it("holds the late answer's clear under the event's waitUntil, past resolving", async () => {
    vi.useFakeTimers();
    const { scope } = fakeScope();
    let release: (inbox: PwaNotifications) => void = () => undefined;
    const remove = vi.fn(async () => ({ Ok: {} }));
    const event = push({ inbox_notification_id: 3 });

    const fetching = fetchPushNotificationPayload(
      source(
        () =>
          new Promise<PwaNotifications>((resolve) => {
            release = resolve;
          }),
      ),
      event,
      scope,
    );
    await vi.advanceTimersByTimeAsync(8_000);
    await expect(fetching).resolves.toMatchObject(GENERIC);

    expect(event.held).toHaveLength(1);
    let settled = false;
    void Promise.all(event.held).then(() => {
      settled = true;
    });
    await vi.advanceTimersByTimeAsync(1_000);
    expect(settled).toBe(false);
    release(over(fakeService({ app_remove_pwa_notification: remove })));
    await Promise.all(event.held);
    removeOf(remove, 3);
  });

  it('asks the event to wait for nothing where there is nothing to report', async () => {
    const { scope } = fakeScope();
    const event = push({ something: 'else' });

    await fetchPushNotificationPayload(
      source(async () => over(fakeService({}))),
      event,
      scope,
    );

    expect(event.held).toHaveLength(0);
  });
});

describe('AuthClient fetchNotificationPayload', () => {
  it('rejects with SessionGoneError where this origin holds no session', async () => {
    const client = new AuthClient({ disableBrowserActivity: true });

    await expect(
      client.fetchNotificationPayload(push({ inbox_notification_id: 3 })),
    ).rejects.toThrow(SessionGoneError);
  });

  it('resolves to the generic notification for a push that names no entry, session or not', async () => {
    vi.stubGlobal('location', { origin: 'https://app.example.com' });
    try {
      const client = new AuthClient({ disableBrowserActivity: true });

      await expect(client.fetchNotificationPayload(push({}))).resolves.toMatchObject(GENERIC);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe('markPushNotificationOpened', () => {
  const click = (data: unknown) => ({ notification: { data } });

  function fakeApp() {
    const opened = vi.fn(async () => undefined);
    vi.spyOn(HttpAgent, 'create').mockResolvedValue({} as HttpAgent);
    const createActor = vi
      .spyOn(Actor, 'createActor')
      .mockReturnValue({ _internet_identity_notification_opened: opened } as never);
    return { opened, createActor };
  }

  const noInbox = async (): Promise<PwaNotifications> => {
    throw new Error('not read for a click');
  };

  it("reports a click on the app's notification to its canister", async () => {
    const { opened, createActor } = fakeApp();

    await markPushNotificationOpened(
      source(noInbox),
      click({ canisterId: 'aaaaa-aa', id: '5', url: 'https://app.example.com/x' }),
    );

    expect(createActor).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ canisterId: Principal.fromText('aaaaa-aa') }),
    );
    expect(opened).toHaveBeenCalledWith(BigInt(5));
  });

  it.each([
    ['no data', null],
    ['the generic notification', undefined],
    ['data of its own', { action: 'reply' }],
    ['a canister that is not a principal', { canisterId: 'not a principal', id: '5' }],
    ['an id that is not a decimal number', { canisterId: 'aaaaa-aa', id: '0x5' }],
    ['an id that is not text', { canisterId: 'aaaaa-aa', id: 5 }],
  ])('ignores a click on a notification with %s', async (_, data) => {
    const { createActor } = fakeApp();

    await expect(markPushNotificationOpened(source(noInbox), click(data))).resolves.toBeUndefined();
    expect(createActor).not.toHaveBeenCalled();
  });

  it('drops a report the canister fails', async () => {
    const { opened } = fakeApp();
    opened.mockRejectedValue(new Error('unreachable'));

    await expect(
      markPushNotificationOpened(source(noInbox), click({ canisterId: 'aaaaa-aa', id: '5' })),
    ).resolves.toBeUndefined();
  });

  it('rejects with SessionGoneError where no session is held', async () => {
    fakeApp();

    await expect(
      markPushNotificationOpened(
        {
          ...source(noInbox),
          identity: async () => {
            throw new SessionGoneError();
          },
        },
        click({ canisterId: 'aaaaa-aa', id: '5' }),
      ),
    ).rejects.toThrow(SessionGoneError);
  });
});

describe('AuthClient markNotificationOpened', () => {
  it("rejects with SessionGoneError for the app's notification where this origin holds no session", async () => {
    const client = new AuthClient({ disableBrowserActivity: true });

    await expect(
      client.markNotificationOpened({
        notification: { data: { canisterId: 'aaaaa-aa', id: '5' } },
      }),
    ).rejects.toThrow(SessionGoneError);
  });

  it('ignores a click on any other notification, session or not', async () => {
    const client = new AuthClient({ disableBrowserActivity: true });

    await expect(
      client.markNotificationOpened({ notification: { data: { url: '/x' } } }),
    ).resolves.toBeUndefined();
  });
});
