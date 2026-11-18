import { Actor, HttpAgent, type Identity, RejectError } from '@icp-sdk/core/agent';
import { IDL } from '@icp-sdk/core/candid';
import type { Principal } from '@icp-sdk/core/principal';
import type { NotificationConsentOptions } from './notification-consent.js';
import type { NotShownReason, PwaNotifications } from './pwa-notifications.js';
import { SessionGoneError } from './session/app-delegation-source.js';

/**
 * How long everything before showing may take, from reading the session to the
 * app's content, before the generic notification is answered instead.
 */
const DISPLAY_DEADLINE_MS = 8_000;

/** The tag of the notification answered where the app's own cannot be, and the prefix of every tag answered here. */
const GENERIC_TAG = 'ii-notification';

/** The part of a service worker's `push` event {@link AuthClient.fetchNotification} reads. */
export interface NotificationPushEvent {
  readonly data: { json(): unknown } | null;
}

/**
 * What the app's canister sent for a notification, carried in the options'
 * `data` for the app's own `notificationclick` handler.
 */
export interface PushNotificationData {
  /** The app's canister, as text. */
  canisterId: string;
  /** The notification's id at that canister, as text. */
  id: string;
  /** Where a click should go, where the canister named a URL on this origin. */
  url?: string;
}

/** What to show for one push, and what to call once it is shown. */
export interface FetchedNotification {
  title: string;
  /** Spread these first into `showNotification`'s options; they carry the `tag`, and `data` for the app's notification. */
  options: NotificationOptions;
  /**
   * Reports the notification shown and clears its entry at Internet Identity.
   * Call it once `showNotification` resolves. Never rejects.
   */
  acknowledge(): Promise<void>;
}

/** What {@link fetchPushNotification} reads the session and the app's canister through. */
export interface PushNotificationSource {
  /** The inbox calls, as the session this origin holds. */
  inbox(): Promise<PwaNotifications>;
  /** The identity the app's canister is called as. */
  identity(): Promise<Identity>;
  /** Options for the agent calling the app's canister. */
  agentOptions: NotificationConsentOptions['agentOptions'];
}

/** The parts of the service worker's global scope a fetch reads. */
export interface PushNotificationScope {
  readonly location: { readonly origin: string };
  /** Absent outside a service worker, where nothing on screen can be closed. */
  readonly registration?: {
    getNotifications(): Promise<{ readonly tag: string; close(): void }[]>;
  };
}

/** A notification's text, as the app's canister answers for it. */
interface NotificationContent {
  title: string;
  body: string;
  url: [] | [string];
}

/** The calls made on the app's canister. */
interface AppNotificationService {
  _internet_identity_notification_content(id: bigint): Promise<[] | [NotificationContent]>;
  _internet_identity_notification_received(id: bigint): Promise<void>;
}

/** The identity-notification library's endpoints on the app's canister. */
const appIdlFactory: IDL.InterfaceFactory = () =>
  IDL.Service({
    _internet_identity_notification_content: IDL.Func(
      [IDL.Nat64],
      [IDL.Opt(IDL.Record({ title: IDL.Text, body: IDL.Text, url: IDL.Opt(IDL.Text) }))],
      ['query'],
    ),
    _internet_identity_notification_received: IDL.Func([IDL.Nat64], [], []),
  });

const appActor = async (
  source: PushNotificationSource,
  canisterId: Principal,
): Promise<AppNotificationService> =>
  Actor.createActor<AppNotificationService>(appIdlFactory, {
    agent: await HttpAgent.create({
      ...source.agentOptions,
      identity: await source.identity(),
    }),
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
const inboxNotificationIdOf = (data: NotificationPushEvent['data']): bigint | undefined => {
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
const closeTagged = async (scope: PushNotificationScope, tag: string): Promise<void> => {
  const shown = await scope.registration?.getNotifications().catch(() => []);
  for (const notification of shown ?? []) {
    if (notification.tag === tag) notification.close();
  }
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
  source: PushNotificationSource,
  scope: PushNotificationScope,
  inboxNotificationId: bigint | undefined,
): Promise<Outcome> {
  if (inboxNotificationId === undefined) return {};

  // Signed out after the push was sent: nothing is shown, so the caller hears it.
  const inbox = await source.inbox().catch((error: unknown) => {
    if (error instanceof SessionGoneError) throw error;
    return undefined;
  });
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
    app = await appActor(source, entry.canister_id);
    content = await app._internet_identity_notification_content(entry.id);
  } catch (error) {
    return { clear, notShown: notShownReasonOf(error) };
  }

  const [shown] = content;
  // The app dismissed it or it expired, so any copy on screen goes too.
  if (shown === undefined) return { closeTag: tag, clear };

  const data: PushNotificationData = {
    canisterId: entry.canister_id.toText(),
    id: entry.id.toString(),
    url: sameOriginUrl(shown.url[0], scope.location.origin),
  };
  return {
    shown: { title: shown.title, options: { body: shown.body, tag, data } },
    closeTag: tag,
    received: () => app._internet_identity_notification_received(entry.id).catch(() => undefined),
    clear,
  };
}

/** Runs `work` the first time it is called, and answers that same run every time after. */
const once = (work: () => Promise<unknown>): (() => Promise<void>) => {
  let running: Promise<void> | undefined;
  return () => {
    running ??= work().then(
      () => undefined,
      () => undefined,
    );
    return running;
  };
};

/** What a `userVisibleOnly` subscription owes the user where nothing better can be shown. */
const generic = async (
  scope: PushNotificationScope,
  acknowledge: () => Promise<unknown> = async () => undefined,
): Promise<FetchedNotification> => {
  await closeTagged(scope, GENERIC_TAG);
  return {
    title: 'New notification',
    options: { tag: GENERIC_TAG },
    acknowledge: once(acknowledge),
  };
};

const globalScope = (): PushNotificationScope => globalThis as unknown as PushNotificationScope;

/**
 * Works out what to show for one push: the app's notification, or the generic
 * one where the payload names no entry, or reading it fails or takes longer than
 * {@link DISPLAY_DEADLINE_MS}, because iOS requires a notification for every
 * push. Rejects only with {@link SessionGoneError}, where no session is held.
 *
 * A copy of the same notification already on screen is closed before this
 * resolves, since iOS ignores `tag` and would show both.
 */
export async function fetchPushNotification(
  source: PushNotificationSource,
  event: NotificationPushEvent,
  scope: PushNotificationScope = globalScope(),
): Promise<FetchedNotification> {
  try {
    const resolving = resolvePush(source, scope, inboxNotificationIdOf(event.data));
    const outcome = await withinDeadline(resolving, DISPLAY_DEADLINE_MS);

    if (outcome === undefined) {
      // The late answer is not shown, and its entry is cleared as one the app could
      // not deliver in time.
      return await generic(scope, async () => {
        const late = await resolving;
        await late.clear?.(late.shown === undefined ? late.notShown : { PayloadUnreachable: null });
      });
    }

    if (outcome.closeTag !== undefined) await closeTagged(scope, outcome.closeTag);
    const { shown, received, clear } = outcome;
    if (shown === undefined) {
      return await generic(scope, async () => clear?.(outcome.notShown));
    }
    return {
      title: shown.title,
      options: shown.options,
      acknowledge: once(() => Promise.all([received?.(), clear?.()])),
    };
  } catch (error) {
    if (error instanceof SessionGoneError) throw error;
    return generic(scope);
  }
}
