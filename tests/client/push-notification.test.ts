import { Actor, AnonymousIdentity, HttpAgent, RejectError } from '@icp-sdk/core/agent';
import { Principal } from '@icp-sdk/core/principal';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthClient } from '../../src/client/auth-client.ts';
import {
  fetchPushNotification,
  markPushNotification,
  type NotificationPushEvent,
  type PushNotificationScope,
  type PushNotificationSource,
} from '../../src/client/push-notification.ts';
import {
  type PwaNotificationService,
  PwaNotifications,
} from '../../src/client/pwa-notifications.ts';
import { SessionGoneError } from '../../src/client/session/app-delegation-source.ts';

/** The private constructor, which is how `notification-consent.test.ts` reaches its own. */
const over = (service: unknown): PwaNotifications =>
  new (PwaNotifications as unknown as new (service: unknown) => PwaNotifications)(service);

function fakeService(answers: Partial<PwaNotificationService>): PwaNotificationService {
  return {
    app_get_pwa_notification: vi.fn(async () => ({ Ok: { notification: [] } })),
    app_remove_pwa_notification: vi.fn(async () => ({ Ok: {} })),
    ...answers,
  } as PwaNotificationService;
}

const GENERIC = {
  title: 'New notification',
  options: { tag: 'ii-notification' },
};

function fakeScope() {
  const getNotifications = vi.fn(async (): Promise<{ tag: string; close(): void }[]> => []);
  return {
    scope: {
      location: { origin: 'https://app.example.com' },
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

const push = (payload: unknown) => ({ data: { json: () => payload } });

/** Fetches for `event`, and marks that same event shown with `mark()`. */
const fetchAndMark = async (
  from: PushNotificationSource,
  event: NotificationPushEvent,
  scope: PushNotificationScope,
) => ({
  ...(await fetchPushNotification(from, event, scope)),
  mark: () => markPushNotification(from, event),
});

const removeOf = (remove: ReturnType<typeof vi.fn>, id: number, notShown: unknown[] = []) =>
  expect(remove).toHaveBeenCalledWith({ inbox_notification_id: BigInt(id), not_shown: notShown });

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('fetchPushNotification', () => {
  it('answers the generic notification for a payload it cannot read, with nothing to mark shown', async () => {
    const remove = vi.fn(async () => ({ Ok: {} }));
    const inbox = vi.fn(async () => over(fakeService({ app_remove_pwa_notification: remove })));
    const { scope } = fakeScope();
    const unreadable = {
      data: {
        json: () => {
          throw new SyntaxError('not JSON');
        },
      },
    };

    const notification = await fetchAndMark(source(inbox), unreadable, scope);
    await notification.mark();

    expect(notification).toMatchObject(GENERIC);
    expect(inbox).not.toHaveBeenCalled();
    expect(remove).not.toHaveBeenCalled();
  });

  it('rejects with SessionGoneError where no session is held', async () => {
    const { scope } = fakeScope();

    await expect(
      fetchAndMark(
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

    const notification = await fetchAndMark(
      source(async () => {
        throw new Error('storage unavailable');
      }),
      push({ inbox_notification_id: 3 }),
      scope,
    );

    expect(notification).toMatchObject(GENERIC);
    await expect(notification.mark()).resolves.toBeUndefined();
  });

  it('answers the generic notification where reading the entry fails, and clears it once marked shown', async () => {
    const remove = vi.fn(async () => ({ Ok: {} }));
    const { scope } = fakeScope();
    const inbox = over(
      fakeService({
        app_get_pwa_notification: vi.fn(async () => ({ Err: { InternalCanisterError: 'down' } })),
        app_remove_pwa_notification: remove,
      }),
    );

    const notification = await fetchAndMark(
      source(async () => inbox),
      push({ inbox_notification_id: 3 }),
      scope,
    );

    expect(notification).toMatchObject(GENERIC);
    expect(remove).not.toHaveBeenCalled();
    await notification.mark();
    removeOf(remove, 3);
  });

  it('closes an earlier generic notification before answering another, since iOS ignores the tag', async () => {
    const { scope, getNotifications } = fakeScope();
    const close = vi.fn();
    getNotifications.mockResolvedValue([{ tag: 'ii-notification', close }]);

    await fetchAndMark(
      source(async () => over(fakeService({}))),
      push({ inbox_notification_id: 3 }),
      scope,
    );

    expect(close).toHaveBeenCalled();
  });

  it('answers the generic notification at the deadline, and clears the late entry once marked shown', async () => {
    vi.useFakeTimers();
    const { scope } = fakeScope();
    let release: (inbox: PwaNotifications) => void = () => undefined;
    const remove = vi.fn(async () => ({ Ok: {} }));

    const fetching = fetchAndMark(
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

    const acknowledging = notification.mark();
    release(over(fakeService({ app_remove_pwa_notification: remove })));
    await acknowledging;
    removeOf(remove, 3);
  });

  it('clears an entry that is gone without a reason', async () => {
    const remove = vi.fn(async () => ({ Ok: {} }));
    const { scope } = fakeScope();

    const notification = await fetchAndMark(
      source(async () => over(fakeService({ app_remove_pwa_notification: remove }))),
      push({ inbox_notification_id: 3 }),
      scope,
    );
    await notification.mark();

    expect(notification).toMatchObject(GENERIC);
    removeOf(remove, 3);
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
            },
          })),
          app_remove_pwa_notification: remove,
        }),
      );
      return { received, remove, inbox };
    }

    it("answers the app's notification with the tag and the data its canister sent", async () => {
      const { inbox } = fakeApp([{ title: 'Hi', body: 'There', url: ['/inbox'] }]);
      const { scope } = fakeScope();

      const notification = await fetchAndMark(
        source(async () => inbox),
        push({ inbox_notification_id: 3 }),
        scope,
      );

      expect(notification.title).toBe('Hi');
      expect(notification.options).toEqual({
        body: 'There',
        tag: 'ii-notification:aaaaa-aa:5',
        data: { canisterId: 'aaaaa-aa', id: '5', url: 'https://app.example.com/inbox' },
      });
    });

    it('reports it received and clears the entry once marked shown, and only once', async () => {
      const { inbox, received, remove } = fakeApp([{ title: 'Hi', body: 'There', url: [] }]);
      const { scope } = fakeScope();

      const notification = await fetchAndMark(
        source(async () => inbox),
        push({ inbox_notification_id: 3 }),
        scope,
      );
      expect(received).not.toHaveBeenCalled();
      expect(remove).not.toHaveBeenCalled();
      await notification.mark();
      await notification.mark();

      expect(received).toHaveBeenCalledTimes(1);
      expect(received).toHaveBeenCalledWith(BigInt(5));
      expect(remove).toHaveBeenCalledTimes(1);
      removeOf(remove, 3);
    });

    it('closes a copy of the same notification already on screen before answering it', async () => {
      const { inbox } = fakeApp([{ title: 'Hi', body: 'There', url: [] }]);
      const { scope, getNotifications } = fakeScope();
      const close = vi.fn();
      getNotifications.mockResolvedValue([{ tag: 'ii-notification:aaaaa-aa:5', close }]);

      await fetchAndMark(
        source(async () => inbox),
        push({ inbox_notification_id: 3 }),
        scope,
      );

      expect(close).toHaveBeenCalled();
    });

    it('answers the generic notification, and clears the entry as rejected, where the canister rejects the call', async () => {
      const { inbox, remove } = fakeApp([]);
      const { scope } = fakeScope();
      vi.mocked(Actor.createActor).mockReturnValue({
        _internet_identity_notification_content: vi.fn(async () => {
          throw Object.create(RejectError.prototype);
        }),
      } as never);

      const notification = await fetchAndMark(
        source(async () => inbox),
        push({ inbox_notification_id: 3 }),
        scope,
      );
      await notification.mark();

      expect(notification).toMatchObject(GENERIC);
      removeOf(remove, 3, [{ PayloadRejected: null }]);
    });

    it('closes a dismissed notification on screen, answers the generic one, and clears the entry without a reason', async () => {
      const { inbox, remove } = fakeApp([]);
      const { scope, getNotifications } = fakeScope();
      const close = vi.fn();
      getNotifications.mockResolvedValue([{ tag: 'ii-notification:aaaaa-aa:5', close }]);

      const notification = await fetchAndMark(
        source(async () => inbox),
        push({ inbox_notification_id: 3 }),
        scope,
      );
      await notification.mark();

      expect(close).toHaveBeenCalled();
      expect(notification).toMatchObject(GENERIC);
      removeOf(remove, 3);
    });

    it('never shows an answer that arrives after the deadline, and clears it as unreachable', async () => {
      vi.useFakeTimers();
      const { inbox, received, remove } = fakeApp([{ title: 'Hi', body: 'There', url: [] }]);
      const { scope } = fakeScope();
      let release: () => void = () => undefined;

      const fetching = fetchAndMark(
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
      const acknowledging = notification.mark();
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

      const notification = await fetchAndMark(
        source(async () => inbox),
        push({ inbox_notification_id: 3 }),
        scope,
      );
      await notification.mark();

      expect(notification).toMatchObject(GENERIC);
      removeOf(remove, 3, [{ PayloadUnreachable: null }]);
    });
  });
});

describe('markPushNotification for a push', () => {
  it('does nothing for a push it never fetched', async () => {
    const remove = vi.fn(async () => ({ Ok: {} }));
    const inbox = vi.fn(async () => over(fakeService({ app_remove_pwa_notification: remove })));

    await expect(
      markPushNotification(source(inbox), push({ inbox_notification_id: 3 })),
    ).resolves.toBeUndefined();

    expect(inbox).not.toHaveBeenCalled();
    expect(remove).not.toHaveBeenCalled();
  });

  it('marks only the event it fetched for, not another with the same payload', async () => {
    const remove = vi.fn(async () => ({ Ok: {} }));
    const from = source(async () => over(fakeService({ app_remove_pwa_notification: remove })));
    const { scope } = fakeScope();
    await fetchPushNotification(from, push({ inbox_notification_id: 3 }), scope);

    await markPushNotification(from, push({ inbox_notification_id: 3 }));

    expect(remove).not.toHaveBeenCalled();
  });
});

describe('AuthClient fetchNotification', () => {
  it('rejects with SessionGoneError where this origin holds no session', async () => {
    const client = new AuthClient({ disableBrowserActivity: true });

    await expect(client.fetchNotification(push({ inbox_notification_id: 3 }))).rejects.toThrow(
      SessionGoneError,
    );
  });

  it('resolves to the generic notification for a push that names no entry, session or not', async () => {
    vi.stubGlobal('location', { origin: 'https://app.example.com' });
    try {
      const client = new AuthClient({ disableBrowserActivity: true });

      await expect(client.fetchNotification(push({}))).resolves.toMatchObject(GENERIC);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe('markPushNotification for a click', () => {
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

    await markPushNotification(
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

    await expect(markPushNotification(source(noInbox), click(data))).resolves.toBeUndefined();
    expect(createActor).not.toHaveBeenCalled();
  });

  it('drops a report the canister fails', async () => {
    const { opened } = fakeApp();
    opened.mockRejectedValue(new Error('unreachable'));

    await expect(
      markPushNotification(source(noInbox), click({ canisterId: 'aaaaa-aa', id: '5' })),
    ).resolves.toBeUndefined();
  });

  it('rejects with SessionGoneError where no session is held', async () => {
    fakeApp();

    await expect(
      markPushNotification(
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

describe('AuthClient markNotification', () => {
  it("rejects with SessionGoneError for the app's notification where this origin holds no session", async () => {
    const client = new AuthClient({ disableBrowserActivity: true });

    await expect(
      client.markNotification({
        notification: { data: { canisterId: 'aaaaa-aa', id: '5' } },
      }),
    ).rejects.toThrow(SessionGoneError);
  });

  it('ignores a click on any other notification, session or not', async () => {
    const client = new AuthClient({ disableBrowserActivity: true });

    await expect(
      client.markNotification({ notification: { data: { url: '/x' } } }),
    ).resolves.toBeUndefined();
  });
});
