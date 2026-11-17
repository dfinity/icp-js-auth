import { describe, expect, it, vi } from 'vitest';
import {
  type PwaNotificationService,
  PwaNotifications,
  pwaAccess,
} from '../../src/client/pwa-notifications.ts';
import { SessionGoneError } from '../../src/client/session/app-delegation-source.ts';
import { handleNotifications, type NotificationWorkerScope } from '../../src/worker/index.ts';

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

describe('handleNotifications', () => {
  function fakeScope() {
    const listeners = new Map<string, (event: unknown) => void>();
    const showNotification = vi.fn(async () => undefined);
    const scope = {
      registration: {
        showNotification,
        getNotifications: vi.fn(async () => []),
        scope: 'https://app.example.com/',
      },
      location: { origin: 'https://app.example.com', hostname: 'app.example.com' },
      clients: { matchAll: vi.fn(async () => []), openWindow: vi.fn(async () => null) },
      addEventListener: (type: string, listener: (event: unknown) => void) =>
        listeners.set(type, listener),
    };
    const push = async (payload: unknown) => {
      let work: Promise<unknown> = Promise.resolve();
      listeners.get('push')?.({
        data: { json: () => payload },
        waitUntil: (promise: Promise<unknown>) => {
          work = promise;
        },
      });
      await work;
    };
    const click = async (data: unknown) => {
      let work: Promise<unknown> = Promise.resolve();
      listeners.get('notificationclick')?.({
        notification: { data, close: vi.fn() },
        waitUntil: (promise: Promise<unknown>) => {
          work = promise;
        },
      });
      await work;
    };
    return {
      scope: scope as unknown as NotificationWorkerScope,
      showNotification,
      push,
      click,
      openWindow: scope.clients.openWindow,
    };
  }

  function fakeClient(
    inbox: () => Promise<PwaNotifications>,
    getIdentity = vi.fn(async () => {
      throw new SessionGoneError();
    }),
  ) {
    const client = { getIdentity };
    pwaAccess.set(client, { inbox, agentOptions: undefined });
    return client as unknown as Parameters<typeof handleNotifications>[0];
  }

  it('shows the generic notification for a payload it cannot read', async () => {
    const { scope, showNotification, push } = fakeScope();
    handleNotifications(
      fakeClient(async () => over(fakeService({}))),
      scope,
    );

    await push({ something: 'else' });

    expect(showNotification).toHaveBeenCalledWith('New notification from app.example.com', {
      tag: 'ii-notification',
    });
  });

  it('shows the generic notification where no session is held', async () => {
    const { scope, showNotification, push } = fakeScope();
    handleNotifications(
      fakeClient(async () => {
        throw new SessionGoneError();
      }),
      scope,
    );

    await push({ inbox_notification_id: 3 });

    expect(showNotification).toHaveBeenCalledTimes(1);
  });

  it('shows the generic notification and clears the entry where reading it fails', async () => {
    const { scope, showNotification, push } = fakeScope();
    const remove = vi.fn(async () => ({ Ok: {} }));
    handleNotifications(
      fakeClient(async () =>
        over(
          fakeService({
            app_get_pwa_notification: vi.fn(async () => ({
              Err: { InternalCanisterError: 'down' },
            })),
            app_remove_pwa_notification: remove,
          }),
        ),
      ),
      scope,
    );

    await push({ inbox_notification_id: 3 });

    expect(showNotification).toHaveBeenCalledTimes(1);
    expect(remove).toHaveBeenCalledWith({ inbox_notification_id: BigInt(3), not_shown: [] });
  });

  it('shows the generic notification for an entry that is gone and nothing on screen', async () => {
    const { scope, showNotification, push } = fakeScope();
    handleNotifications(
      fakeClient(async () => over(fakeService({}))),
      scope,
    );

    await push({ inbox_notification_id: 3 });

    expect(showNotification).toHaveBeenCalledTimes(1);
  });

  it('reports a click on a notification without a url as opened, after opening the app', async () => {
    const { scope, click, openWindow } = fakeScope();
    const getIdentity = vi.fn(async () => {
      throw new SessionGoneError();
    });
    handleNotifications(
      fakeClient(async () => over(fakeService({})), getIdentity),
      scope,
    );

    await click({ canisterId: 'aaaaa-aa', id: '5' });

    expect(openWindow).toHaveBeenCalledWith('https://app.example.com/');
    expect(getIdentity).toHaveBeenCalled();
  });

  it('reports nothing for a click on the generic notification', async () => {
    const { scope, click } = fakeScope();
    const getIdentity = vi.fn(async () => {
      throw new SessionGoneError();
    });
    handleNotifications(
      fakeClient(async () => over(fakeService({})), getIdentity),
      scope,
    );

    await click(null);

    expect(getIdentity).not.toHaveBeenCalled();
  });

  it('refuses anything other than an AuthClient', () => {
    expect(() =>
      handleNotifications({} as Parameters<typeof handleNotifications>[0], fakeScope().scope),
    ).toThrow('handleNotifications takes an AuthClient');
  });
});
