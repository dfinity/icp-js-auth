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

/**
 * How long everything before showing may take, from reading the session to the
 * app's content, before the generic notification is shown instead.
 */
const DISPLAY_DEADLINE_MS = 8_000;

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

/** `work`'s result, or `undefined` where it takes longer than `deadlineMs`. */
const withinDeadline = async <T>(work: Promise<T>, deadlineMs: number): Promise<T | undefined> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<undefined>((resolve) => {
        timer = setTimeout(() => resolve(undefined), deadlineMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};

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

/** What one wake-up comes to, worked out before anything is shown. */
interface Outcome {
  /** The app's notification, or the generic one where absent. */
  shown?: { title: string; options: NotificationOptions };
  /** A copy of this notification already on screen, closed before anything is shown. */
  closeTag?: string;
  /** Reports the notification received to the app, once it is shown. */
  received?: () => Promise<void>;
  /** Clears the entry at Internet Identity, with why it was not shown where it was not. */
  clear?: (notShown?: NotShownReason) => Promise<void>;
  /** Why the app's notification could not be shown. */
  notShown?: NotShownReason;
}

/**
 * Reads the entry a wake-up names and the app's content for it. Shows nothing,
 * so a result that arrives after the deadline cannot put a second notification
 * on screen.
 */
async function resolvePush(
  scope: NotificationWorkerScope,
  authClient: AuthClient,
  access: PwaAccess,
  inboxNotificationId: bigint | undefined,
): Promise<Outcome> {
  if (inboxNotificationId === undefined) return {};

  // Signed out after the push was sent: nothing can be read.
  const inbox = await access.inbox().catch(() => undefined);
  if (inbox === undefined) return {};

  const clear = (notShown?: NotShownReason): Promise<void> =>
    inbox.remove(inboxNotificationId, notShown).catch(() => undefined);

  const entry = await inbox.get(inboxNotificationId).catch(() => null);
  // Unreadable, expired or already taken. Cleared anyway, so an expired entry is
  // counted as one asked for too late.
  if (entry === null || entry === undefined) return { clear };

  const tag = tagOf(entry.canister_id, entry.id);
  let app: AppNotificationService;
  let content: [] | [NotificationContent];
  try {
    app = await appActor(access, await authClient.getIdentity(), entry.canister_id);
    content = await app._internet_identity_notification_content(entry.id);
  } catch (error) {
    return { clear, notShown: notShownReasonOf(error) };
  }

  const [shown] = content;
  // The app dismissed it or it expired, so any copy on screen goes too.
  if (shown === undefined) return { closeTag: tag, clear };

  const url = sameOriginUrl(shown.url[0], scope.location.origin);
  const data: ShownData = { canisterId: entry.canister_id.toText(), id: entry.id.toString(), url };
  return {
    shown: { title: shown.title, options: { body: shown.body, tag, data } },
    closeTag: tag,
    received: () => app._internet_identity_notification_received(entry.id).catch(() => undefined),
    clear,
  };
}

/**
 * One wake-up: show the app's notification for it, or the generic one, and
 * clear its entry. Something is shown for every push, because Safari requires
 * it of a `userVisibleOnly` subscription.
 */
async function onPush(
  scope: NotificationWorkerScope,
  authClient: AuthClient,
  access: PwaAccess,
  inboxNotificationId: bigint | undefined,
): Promise<void> {
  const resolving = resolvePush(scope, authClient, access, inboxNotificationId);
  const outcome = await withinDeadline(resolving, DISPLAY_DEADLINE_MS);

  if (outcome === undefined) {
    await showGeneric(scope);
    // The late answer is not shown, and its entry is cleared as one the app could
    // not deliver in time.
    const late = await resolving;
    await late.clear?.(late.shown === undefined ? late.notShown : { PayloadUnreachable: null });
    return;
  }

  if (outcome.closeTag !== undefined) await closeTagged(scope.registration, outcome.closeTag);
  if (outcome.shown === undefined) {
    await showGeneric(scope);
    await outcome.clear?.(outcome.notShown);
    return;
  }

  await scope.registration.showNotification(outcome.shown.title, outcome.shown.options);
  await Promise.all([outcome.received?.(), outcome.clear?.()]);
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

/** Focuses a window within the worker's scope, or opens the scope. */
const openTheApp = async (scope: NotificationWorkerScope): Promise<void> => {
  const windows = await scope.clients.matchAll({ type: 'window', includeUncontrolled: true });
  const open = windows.find((client) => client.url.startsWith(scope.registration.scope));
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
        if (data === undefined) return;
        const identity = await authClient.getIdentity();
        const app = await appActor(access, identity, Principal.fromText(data.canisterId));
        await app._internet_identity_notification_opened(BigInt(data.id));
      })().catch(() => undefined),
    );
  });
}
