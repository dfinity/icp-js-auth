/**
 * The service worker side of notifications in an installed web app.
 *
 * The application keeps its own service worker and calls
 * {@link handleNotifications} from it. Nothing is held here between events: the
 * session is read from the {@link AuthClient}'s storage, which the page writes,
 * on every event.
 *
 * @module api/worker
 */

import { Actor, HttpAgent, type Identity, RejectError } from '@icp-sdk/core/agent';
import { IDL } from '@icp-sdk/core/candid';
import { Principal } from '@icp-sdk/core/principal';
import type { AuthClient } from '../client/auth-client.js';
import { type NotShownReason, type PwaAccess, pwaAccess } from '../client/pwa-notifications.js';

/** How long the app's content may take before the generic notification is shown instead. */
const CONTENT_DEADLINE_MS = 8_000;

const GENERIC_TAG = 'ii-notification';

/** What a push event carries, of the service worker types the DOM library lacks. */
interface PushEvent extends Event {
  readonly data: { json(): unknown } | null;
  waitUntil(work: Promise<unknown>): void;
}

interface NotificationClickEvent extends Event {
  readonly notification: Notification;
  waitUntil(work: Promise<unknown>): void;
}

interface WindowClient {
  readonly url: string;
  focus(): Promise<WindowClient>;
}

/** The parts of a service worker's global scope these handlers use. */
export interface NotificationWorkerScope {
  readonly registration: ServiceWorkerRegistration;
  readonly location: { readonly origin: string; readonly hostname: string };
  readonly clients: {
    matchAll(options: { type: 'window'; includeUncontrolled: boolean }): Promise<WindowClient[]>;
    openWindow(url: string): Promise<WindowClient | null>;
  };
  addEventListener(type: 'push', listener: (event: PushEvent) => void): void;
  addEventListener(
    type: 'notificationclick',
    listener: (event: NotificationClickEvent) => void,
  ): void;
}

/** What a shown notification carries for its click. */
interface ShownData {
  canisterId: string;
  id: string;
  url?: string;
}

interface NotificationContent {
  title: string;
  body: string;
  url: [] | [string];
}

interface AppNotificationService {
  _internet_identity_notification_content(id: bigint): Promise<[] | [NotificationContent]>;
  _internet_identity_notification_received(id: bigint): Promise<void>;
  _internet_identity_notification_opened(id: bigint): Promise<void>;
}

/** The identity-notification library's endpoints on the dapp's canister. */
const appIdlFactory: IDL.InterfaceFactory = () =>
  IDL.Service({
    _internet_identity_notification_content: IDL.Func(
      [IDL.Nat64],
      [IDL.Opt(IDL.Record({ title: IDL.Text, body: IDL.Text, url: IDL.Opt(IDL.Text) }))],
      ['query'],
    ),
    _internet_identity_notification_received: IDL.Func([IDL.Nat64], [], []),
    _internet_identity_notification_opened: IDL.Func([IDL.Nat64], [], []),
  });

const appActor = async (
  access: PwaAccess,
  identity: Identity,
  canisterId: Principal,
): Promise<AppNotificationService> =>
  Actor.createActor<AppNotificationService>(appIdlFactory, {
    agent: await HttpAgent.create({ ...access.agentOptions, identity }),
    canisterId,
  });

class DeadlineError extends Error {}

const withDeadline = <T>(work: Promise<T>, deadlineMs: number): Promise<T> =>
  Promise.race([
    work,
    new Promise<never>((_, reject) => setTimeout(() => reject(new DeadlineError()), deadlineMs)),
  ]);

/** The inbox entry a wake-up names, or `undefined` where its payload is not one. */
const inboxNotificationIdOf = (data: PushEvent['data']): bigint | undefined => {
  try {
    const payload: unknown = data?.json();
    if (payload === null || typeof payload !== 'object') return undefined;
    const { inbox_notification_id } = payload as Record<string, unknown>;
    if (typeof inbox_notification_id !== 'number' || !Number.isSafeInteger(inbox_notification_id)) {
      return undefined;
    }
    return BigInt(inbox_notification_id);
  } catch {
    return undefined;
  }
};

const tagOf = (canisterId: Principal, id: bigint): string =>
  `${GENERIC_TAG}:${canisterId.toText()}:${id}`;

/** iOS ignores `tag`, so a notification is replaced by closing the old one by hand. */
const closeTagged = async (registration: ServiceWorkerRegistration, tag: string): Promise<void> => {
  for (const shown of await registration.getNotifications()) {
    if (shown.tag === tag) shown.close();
  }
};

/** What a `userVisibleOnly` subscription owes the user where nothing better can be shown. */
const showGeneric = async (scope: NotificationWorkerScope): Promise<void> => {
  await closeTagged(scope.registration, GENERIC_TAG);
  await scope.registration.showNotification(`New notification from ${scope.location.hostname}`, {
    tag: GENERIC_TAG,
  });
};

/** The generic notification, unless something is already on screen. */
const showGenericIfNothingShown = async (scope: NotificationWorkerScope): Promise<void> => {
  if ((await scope.registration.getNotifications()).length > 0) return;
  await showGeneric(scope);
};

/** `url` where it is on this origin, resolved against it. */
const sameOriginUrl = (url: string | undefined, origin: string): string | undefined => {
  if (url === undefined) return undefined;
  try {
    const resolved = new URL(url, origin);
    return resolved.origin === origin ? resolved.href : undefined;
  } catch {
    return undefined;
  }
};

const notShownReasonOf = (error: unknown): NotShownReason =>
  error instanceof RejectError ? { PayloadRejected: null } : { PayloadUnreachable: null };

/** One wake-up: read the entry, fetch and show its content, report it, and clear it. */
async function onPush(
  scope: NotificationWorkerScope,
  authClient: AuthClient,
  access: PwaAccess,
  inboxNotificationId: bigint | undefined,
): Promise<void> {
  if (inboxNotificationId === undefined) {
    await showGeneric(scope);
    return;
  }

  // Signed out after the push was sent: nothing can be read, and iOS still needs
  // a notification.
  const inbox = await access.inbox().catch(() => undefined);
  if (inbox === undefined) {
    await showGeneric(scope);
    return;
  }

  const remove = (notShown?: NotShownReason): Promise<void> =>
    inbox.remove(inboxNotificationId, notShown).catch(() => undefined);

  const entry = await inbox.get(inboxNotificationId).catch(() => null);
  if (entry === null) {
    await showGeneric(scope);
    await remove();
    return;
  }
  if (entry === undefined) {
    await showGenericIfNothingShown(scope);
    return;
  }

  const tag = tagOf(entry.canister_id, entry.id);
  let app: AppNotificationService;
  let content: [] | [NotificationContent];
  try {
    ({ app, content } = await withDeadline(
      (async () => {
        const app = await appActor(access, await authClient.getIdentity(), entry.canister_id);
        return { app, content: await app._internet_identity_notification_content(entry.id) };
      })(),
      CONTENT_DEADLINE_MS,
    ));
  } catch (error) {
    await showGeneric(scope);
    await remove(notShownReasonOf(error));
    return;
  }

  const [shown] = content;
  if (shown === undefined) {
    // The app dismissed it or it expired, so any copy on screen goes too.
    await closeTagged(scope.registration, tag);
    await showGenericIfNothingShown(scope);
    await remove();
    return;
  }

  const url = sameOriginUrl(shown.url[0], scope.location.origin);
  const data: ShownData = { canisterId: entry.canister_id.toText(), id: entry.id.toString(), url };
  await closeTagged(scope.registration, tag);
  await scope.registration.showNotification(shown.title, { body: shown.body, tag, data });

  await Promise.all([
    app._internet_identity_notification_received(entry.id).catch(() => undefined),
    remove(),
  ]);
}

const shownDataOf = (data: unknown): ShownData | undefined => {
  if (data === null || typeof data !== 'object') return undefined;
  const { canisterId, id, url } = data as Record<string, unknown>;
  if (typeof canisterId !== 'string' || typeof id !== 'string') return undefined;
  return { canisterId, id, url: typeof url === 'string' ? url : undefined };
};

/** Focuses a window of this app on `url`, or opens one there. */
const openAt = async (scope: NotificationWorkerScope, url: string): Promise<void> => {
  const windows = await scope.clients.matchAll({ type: 'window', includeUncontrolled: true });
  const open = windows.find((client) => client.url === url);
  if (open !== undefined) {
    await open.focus();
    return;
  }
  await scope.clients.openWindow(url);
};

/** Focuses any window of this app, or opens its start. */
const openTheApp = async (scope: NotificationWorkerScope): Promise<void> => {
  const windows = await scope.clients.matchAll({ type: 'window', includeUncontrolled: true });
  const open = windows.find((client) => client.url.startsWith(scope.location.origin));
  if (open !== undefined) {
    await open.focus();
    return;
  }
  await scope.clients.openWindow(scope.registration.scope);
};

/**
 * Adds the `push` and `notificationclick` listeners that show this
 * application's notifications in its installed web app.
 *
 * Call it once, at the top level of the application's own service worker, with
 * an {@link AuthClient} built with the same options as the page's, so it reads
 * the session the page signed in with. On a push it reads the inbox entry the
 * push names from Internet Identity, fetches the content from the application's
 * canister, shows it, reports it received, and clears the entry. Where any of
 * that fails, or no session is held, it shows a generic notification, because
 * iOS requires one for every push.
 *
 * @param authClient - The client whose session the calls are made as.
 * @param scope - The service worker's global scope.
 * @example
 * // service-worker.ts
 * import { AuthClient } from '@icp-sdk/auth/client';
 * import { handleNotifications } from '@icp-sdk/auth/worker';
 *
 * handleNotifications(new AuthClient());
 */
export function handleNotifications(
  authClient: AuthClient,
  scope: NotificationWorkerScope = globalThis as unknown as NotificationWorkerScope,
): void {
  const access = pwaAccess.get(authClient);
  if (access === undefined) throw new Error('handleNotifications takes an AuthClient');

  scope.addEventListener('push', (event) => {
    event.waitUntil(
      onPush(scope, authClient, access, inboxNotificationIdOf(event.data)).catch(() =>
        showGeneric(scope),
      ),
    );
  });

  scope.addEventListener('notificationclick', (event) => {
    event.notification.close();
    const data = shownDataOf(event.notification.data);
    const url = sameOriginUrl(data?.url, scope.location.origin);
    // Started before anything is awaited: a window may be opened only while the
    // click is being handled.
    const opening = url === undefined ? openTheApp(scope) : openAt(scope, url);
    event.waitUntil(
      (async () => {
        await opening.catch(() => undefined);
        if (data === undefined || url === undefined) return;
        const identity = await authClient.getIdentity();
        const app = await appActor(access, identity, Principal.fromText(data.canisterId));
        await app._internet_identity_notification_opened(BigInt(data.id));
      })().catch(() => undefined),
    );
  });
}
