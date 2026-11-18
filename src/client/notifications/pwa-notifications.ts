import { Actor, HttpAgent } from '@icp-sdk/core/agent';
import type { IDL } from '@icp-sdk/core/candid';
import { DelegationIdentity } from '@icp-sdk/core/identity';
import type { Principal } from '@icp-sdk/core/principal';
import { fromBase64, toBase64 } from '../base64.js';
import { IdbKeyVal } from '../db.js';
import { SessionGoneError } from '../session/app-delegation-source.js';
import { assertChainReaches } from '../session/session-minter.js';
import type { NotificationConsentOptions } from './notification-consent.js';

/**
 * Whether this page runs as an installed web app of Safari (an iOS Home Screen
 * app or a macOS Dock app), which keeps storage of its own apart from Safari's.
 *
 * Only Safari reports `navigator.standalone`. Installed apps of Chromium share
 * the browser's storage, and with it the browser's entry at Internet Identity,
 * in every display mode.
 */
export function isSafariInstalledApp(): boolean {
  const navigator = globalThis.navigator as (Navigator & { standalone?: boolean }) | undefined;
  return navigator?.standalone === true;
}

/**
 * Whether this installed app is linked to the Safari of the same device.
 *
 * - `linked`: it is, so Internet Identity delivers this application's
 *   notifications on this device only to this app.
 * - `other-path-may-deliver`: it is not, and another path of this identity may
 *   deliver them too, so linking would stop a second copy.
 * - `no-other-path`: there is nothing to link.
 */
export type SameDeviceLinkStatus = 'linked' | 'other-path-may-deliver' | 'no-other-path';

type CandidSameDeviceLinkStatus =
  | { Linked: null }
  | { OtherPathMayDeliver: null }
  | { NoOtherPath: null };

/** Why the service worker could not show a notification. */
export type NotShownReason = { PayloadUnreachable: null } | { PayloadRejected: null };

/** Why Internet Identity handed out no subscription keys. */
type PrepareError =
  | { NoSuchSession: null }
  | { NotificationsNotAllowed: null }
  | { NoSuchFrontend: null }
  | { InternalCanisterError: string };

/** Why Internet Identity did not register or remove a subscription. */
type SubscriptionError =
  | { NoSuchSession: null }
  | { NotificationsNotAllowed: null }
  | { TransportKeyExpired: null }
  | { EndpointInUse: null }
  | { InternalCanisterError: string };

/** Why Internet Identity could not answer an inbox or status call. */
type NotificationError = { NoSuchSession: null } | { InternalCanisterError: string };

/** A push subscription as Internet Identity registers it, with `auth` sealed to its transport key. */
interface SealedSubscription {
  endpoint: string;
  p256dh: Uint8Array;
  transport_key: Uint8Array;
  sealed_auth: Uint8Array;
}

/** An inbox entry the wake-up named: the canister holding its content, and which one. */
export interface PwaNotification {
  canister_id: Principal;
  id: bigint;
}

/**
 * The frontend a subscription call is made for, which Internet Identity keeps a
 * subscription per browser for.
 */
interface FrontendRequest {
  frontend_origin: [] | [string];
}

/** The Internet Identity methods an installed app's subscription is made of. */
export interface PwaNotificationService {
  app_prepare_pwa_webpush_subscription(
    request: [] | [FrontendRequest],
  ): Promise<
    | { Ok: { vapid_public_key: Uint8Array; transport_public_key: Uint8Array } }
    | { Pending: null }
    | { Err: PrepareError }
  >;
  app_set_pwa_webpush_subscription(
    request: FrontendRequest & { subscription: [] | [SealedSubscription] },
  ): Promise<{ Ok: null } | { Err: SubscriptionError }>;
  app_get_pwa_webpush_subscription_status(
    request: [] | [FrontendRequest],
  ): Promise<{ Ok: [] | [{ endpoint: string }] } | { Err: NotificationError }>;
  app_get_pwa_notification(request: {
    inbox_notification_id: bigint;
  }): Promise<{ Ok: { notification: [] | [PwaNotification] } } | { Err: NotificationError }>;
  app_remove_pwa_notification(
    request: FrontendRequest & {
      inbox_notification_id: bigint;
      not_shown: [] | [NotShownReason];
    },
  ): Promise<{ Ok: Record<string, never> } | { Err: NotificationError }>;
  app_get_same_device_link_status(): Promise<
    { Ok: CandidSameDeviceLinkStatus } | { Err: NotificationError }
  >;
  app_prepare_same_device_link(request: {
    link_public_key: Uint8Array;
  }): Promise<{ Ok: null } | { Err: NotificationError }>;
}

/** Written out because this package carries no Internet Identity declarations. */
const idlFactory: IDL.InterfaceFactory = ({ IDL }) => {
  const PrepareError = IDL.Variant({
    NoSuchSession: IDL.Null,
    NotificationsNotAllowed: IDL.Null,
    NoSuchFrontend: IDL.Null,
    InternalCanisterError: IDL.Text,
  });
  const FrontendRequest = IDL.Record({ frontend_origin: IDL.Opt(IDL.Text) });
  const SubscriptionError = IDL.Variant({
    NoSuchSession: IDL.Null,
    NotificationsNotAllowed: IDL.Null,
    TransportKeyExpired: IDL.Null,
    EndpointInUse: IDL.Null,
    InternalCanisterError: IDL.Text,
  });
  const NotificationError = IDL.Variant({
    NoSuchSession: IDL.Null,
    InternalCanisterError: IDL.Text,
  });
  const PwaNotification = IDL.Record({ canister_id: IDL.Principal, id: IDL.Nat64 });
  const NotShownReason = IDL.Variant({ PayloadUnreachable: IDL.Null, PayloadRejected: IDL.Null });
  return IDL.Service({
    app_prepare_pwa_webpush_subscription: IDL.Func(
      [IDL.Opt(FrontendRequest)],
      [
        IDL.Variant({
          Ok: IDL.Record({
            vapid_public_key: IDL.Vec(IDL.Nat8),
            transport_public_key: IDL.Vec(IDL.Nat8),
          }),
          Pending: IDL.Null,
          Err: PrepareError,
        }),
      ],
      [],
    ),
    app_set_pwa_webpush_subscription: IDL.Func(
      [
        IDL.Record({
          subscription: IDL.Opt(
            IDL.Record({
              endpoint: IDL.Text,
              p256dh: IDL.Vec(IDL.Nat8),
              transport_key: IDL.Vec(IDL.Nat8),
              sealed_auth: IDL.Vec(IDL.Nat8),
            }),
          ),
          frontend_origin: IDL.Opt(IDL.Text),
        }),
      ],
      [IDL.Variant({ Ok: IDL.Null, Err: SubscriptionError })],
      [],
    ),
    app_get_pwa_webpush_subscription_status: IDL.Func(
      [IDL.Opt(FrontendRequest)],
      [
        IDL.Variant({
          Ok: IDL.Opt(IDL.Record({ endpoint: IDL.Text })),
          Err: NotificationError,
        }),
      ],
      ['query'],
    ),
    app_get_pwa_notification: IDL.Func(
      [IDL.Record({ inbox_notification_id: IDL.Nat64 })],
      [
        IDL.Variant({
          Ok: IDL.Record({ notification: IDL.Opt(PwaNotification) }),
          Err: NotificationError,
        }),
      ],
      ['query'],
    ),
    app_remove_pwa_notification: IDL.Func(
      [
        IDL.Record({
          inbox_notification_id: IDL.Nat64,
          not_shown: IDL.Opt(NotShownReason),
          frontend_origin: IDL.Opt(IDL.Text),
        }),
      ],
      [IDL.Variant({ Ok: IDL.Record({}), Err: NotificationError })],
      [],
    ),
    app_get_same_device_link_status: IDL.Func(
      [],
      [
        IDL.Variant({
          Ok: IDL.Variant({
            Linked: IDL.Null,
            OtherPathMayDeliver: IDL.Null,
            NoOtherPath: IDL.Null,
          }),
          Err: NotificationError,
        }),
      ],
      ['query'],
    ),
    app_prepare_same_device_link: IDL.Func(
      [IDL.Record({ link_public_key: IDL.Vec(IDL.Nat8) })],
      [IDL.Variant({ Ok: IDL.Null, Err: NotificationError })],
      [],
    ),
  });
};

/**
 * Thrown where the push endpoint is registered by another entry with keys this
 * device did not present. The remedy is a fresh endpoint, which
 * {@link subscribeDevice} takes once on its own.
 */
class EndpointInUseError extends Error {
  constructor() {
    super('This push endpoint is registered with other keys');
    this.name = 'EndpointInUseError';
  }
}

/**
 * Thrown where the identity has not allowed this application to notify it, so
 * Internet Identity holds no subscription for it.
 */
export class NotificationsNotAllowedError extends Error {
  constructor() {
    super('The user has not allowed this application to notify them');
    this.name = 'NotificationsNotAllowedError';
  }
}

const unwrapSubscription = <T>(
  result: { Ok: T } | { Err: PrepareError | SubscriptionError },
): T => {
  if ('Ok' in result) return result.Ok;
  const error = result.Err;
  if ('NoSuchSession' in error) throw new SessionGoneError();
  if ('EndpointInUse' in error) throw new EndpointInUseError();
  if ('NotificationsNotAllowed' in error) throw new NotificationsNotAllowedError();
  if ('NoSuchFrontend' in error) {
    throw new Error("This application lists no frontend at this page's origin");
  }
  if ('TransportKeyExpired' in error) {
    throw new Error('Internet Identity no longer holds the key this subscription was sealed to');
  }
  const detail = error.InternalCanisterError;
  throw new Error(
    `Internet Identity could not register this push subscription${detail === '' ? '' : `: ${detail}`}`,
  );
};

const unwrapNotification = <T>(
  result: { Ok: T } | { Err: NotificationError },
  failed: string,
): T => {
  if ('Ok' in result) return result.Ok;
  if ('NoSuchSession' in result.Err) throw new SessionGoneError();
  const detail = result.Err.InternalCanisterError;
  throw new Error(`${failed}${detail === '' ? '' : `: ${detail}`}`);
};

/** How much longer each ask after the first waits than the one before it. */
const PREPARE_RETRY_STEP_MS = 1_000;

/** Enough asks to outlast Internet Identity fetching its VAPID key or drawing randomness. */
const PREPARE_ATTEMPTS = 4;

const wait = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** The keys a subscribe needs. */
export interface SubscriptionKeys {
  /** Internet Identity's VAPID public key, which the push subscription is bound to. */
  vapidPublicKey: Uint8Array;
  /** Minted for this caller and this attempt; `auth` is sealed to it. */
  transportPublicKey: Uint8Array;
}

/**
 * An installed app's push subscription and inbox at Internet Identity, called as
 * the session, for the frontend this page is served from.
 */
export class PwaNotifications {
  readonly #service: PwaNotificationService;
  readonly #frontend: FrontendRequest;

  private constructor(service: PwaNotificationService, frontendOrigin: string) {
    this.#service = service;
    this.#frontend = { frontend_origin: [frontendOrigin] };
  }

  /**
   * As the session, which is what Internet Identity reads the identity, browser
   * and app from, for the frontend at `frontendOrigin`.
   */
  static async create(
    options: NotificationConsentOptions,
    frontendOrigin: string,
  ): Promise<PwaNotifications> {
    const { canisterId } = options;
    assertChainReaches(options.sessionChain, canisterId);
    const agent = await HttpAgent.create({
      ...options.agentOptions,
      identity: DelegationIdentity.fromDelegation(options.sessionKey, options.sessionChain),
    });
    return new PwaNotifications(
      Actor.createActor<PwaNotificationService>(idlFactory, { agent, canisterId }),
      frontendOrigin,
    );
  }

  /**
   * The keys the next subscribe needs, asked for again while Internet Identity
   * answers Pending: it is still fetching its VAPID key or drawing randomness.
   */
  async prepare(): Promise<SubscriptionKeys> {
    for (let attempt = 0; attempt < PREPARE_ATTEMPTS; attempt++) {
      if (attempt > 0) await wait(attempt * PREPARE_RETRY_STEP_MS);
      const response = await this.#service.app_prepare_pwa_webpush_subscription([this.#frontend]);
      if ('Pending' in response) continue;
      const keys = unwrapSubscription(response);
      return {
        vapidPublicKey: new Uint8Array(keys.vapid_public_key),
        transportPublicKey: new Uint8Array(keys.transport_public_key),
      };
    }
    throw new Error('Internet Identity is not ready to hand out subscription keys yet');
  }

  /** Registers this device's subscription, or removes it where `subscription` is `null`. */
  async set(subscription: SealedSubscription | null): Promise<void> {
    unwrapSubscription(
      await this.#service.app_set_pwa_webpush_subscription({
        ...this.#frontend,
        subscription: subscription === null ? [] : [subscription],
      }),
    );
  }

  /**
   * The endpoint Internet Identity delivers to for this session's browser,
   * account and frontend, or `undefined` where it holds none for them.
   */
  async registeredEndpoint(): Promise<string | undefined> {
    const status = unwrapNotification(
      await this.#service.app_get_pwa_webpush_subscription_status([this.#frontend]),
      'Internet Identity could not read this subscription',
    );
    return status[0]?.endpoint;
  }

  /** The entry a wake-up named, or `undefined` where it is gone. */
  async get(inboxNotificationId: bigint): Promise<PwaNotification | undefined> {
    const found = unwrapNotification(
      await this.#service.app_get_pwa_notification({
        inbox_notification_id: inboxNotificationId,
      }),
      'Internet Identity could not read this notification',
    );
    return found.notification[0];
  }

  /** Clears the entry a wake-up named, with why it was not shown where it was not. */
  async remove(inboxNotificationId: bigint, notShown?: NotShownReason): Promise<void> {
    unwrapNotification(
      await this.#service.app_remove_pwa_notification({
        ...this.#frontend,
        inbox_notification_id: inboxNotificationId,
        not_shown: notShown === undefined ? [] : [notShown],
      }),
      'Internet Identity could not remove this notification',
    );
  }

  /** Whether this installed app is linked to the Safari of the same device. */
  async sameDeviceLinkStatus(): Promise<SameDeviceLinkStatus> {
    const status = unwrapNotification(
      await this.#service.app_get_same_device_link_status(),
      'Internet Identity could not read this link',
    );
    if ('Linked' in status) return 'linked';
    if ('OtherPathMayDeliver' in status) return 'other-path-may-deliver';
    return 'no-other-path';
  }

  /** Registers the public half of the one-shot key that Safari's claim is signed with. */
  async prepareSameDeviceLink(linkPublicKey: Uint8Array): Promise<void> {
    unwrapNotification(
      await this.#service.app_prepare_same_device_link({ link_public_key: linkPublicKey }),
      'Internet Identity could not prepare this link',
    );
  }
}

/** A view's own bytes, which is what WebCrypto's parameters are typed to take. */
const bytesOf = (view: Uint8Array): ArrayBuffer =>
  view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;

// HKDF info prefix and labels. Must match Internet Identity's
// https://github.com/dfinity/internet-identity/blob/main/src/internet_identity/src/notifications/webpush/transport.rs
const INFO_PREFIX = new TextEncoder().encode('II webpush transport\0');
const KEY_LABEL = new TextEncoder().encode('key\0');
const IV_LABEL = new TextEncoder().encode('iv\0');

/** The bits of an ECDH P-256 shared secret. */
const SHARED_SECRET_BITS = 256;

/** The bits of an AES-128-GCM key. */
const AES_KEY_BITS = 128;

/** The bits of an AES-GCM nonce. */
const AES_IV_BITS = 96;

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
};

/**
 * Encrypts `subscription`'s `auth` secret to `transportPublicKey` (ephemeral
 * ECDH P-256, HKDF-SHA-256, AES-128-GCM), so boundary nodes and replicas never
 * see enough to forge a push.
 */
export async function sealSubscription(
  subscription: PushSubscription,
  transportPublicKey: Uint8Array,
): Promise<SealedSubscription> {
  const subscriberKey = subscription.getKey('p256dh');
  const authSecret = subscription.getKey('auth');
  if (subscriberKey === null || authSecret === null) {
    throw new Error('The push subscription carries no encryption keys');
  }
  const { subtle } = globalThis.crypto;

  const browser = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
    'deriveBits',
  ]);
  const transportKey = new Uint8Array(await subtle.exportKey('raw', browser.publicKey));
  const theirs = await subtle.importKey(
    'raw',
    bytesOf(transportPublicKey),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );
  const shared = await subtle.deriveBits(
    { name: 'ECDH', public: theirs },
    browser.privateKey,
    SHARED_SECRET_BITS,
  );
  const extracted = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);

  // The canister's key first and this one second, which is the order it rebuilds in.
  const info = concat(INFO_PREFIX, transportPublicKey, transportKey);
  const derive = (label: Uint8Array, bits: number): Promise<ArrayBuffer> =>
    subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new ArrayBuffer(0),
        info: bytesOf(concat(info, label)),
      },
      extracted,
      bits,
    );

  const key = await subtle.importKey(
    'raw',
    await derive(KEY_LABEL, AES_KEY_BITS),
    'AES-GCM',
    false,
    ['encrypt'],
  );
  const sealedAuth = new Uint8Array(
    await subtle.encrypt(
      { name: 'AES-GCM', iv: await derive(IV_LABEL, AES_IV_BITS) },
      key,
      authSecret,
    ),
  );

  return {
    endpoint: subscription.endpoint,
    p256dh: new Uint8Array(subscriberKey),
    transport_key: transportKey,
    sealed_auth: sealedAuth,
  };
}

/** Whether `subscription` was minted with `applicationServerKey`. */
export const subscribedWith = (
  subscription: PushSubscription,
  applicationServerKey: Uint8Array,
): boolean => {
  const minted = subscription.options.applicationServerKey;
  if (minted === null || minted === undefined) return false;
  const bytes = new Uint8Array(minted);
  return (
    bytes.length === applicationServerKey.length &&
    bytes.every((byte, at) => byte === applicationServerKey[at])
  );
};

/**
 * The registration's push subscription where it is bound to `vapidPublicKey`,
 * otherwise a new one replacing it.
 */
const heldOrNewSubscription = async (
  registration: ServiceWorkerRegistration,
  vapidPublicKey: Uint8Array,
): Promise<PushSubscription> => {
  const held = await registration.pushManager.getSubscription();
  if (held !== null && subscribedWith(held, vapidPublicKey)) return held;
  await held?.unsubscribe();
  return registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: bytesOf(vapidPublicKey),
  });
};

/**
 * Subscribes `registration` with Internet Identity's VAPID key, replacing a
 * subscription under any other key, and registers the subscription for the
 * session behind `inbox`, retrying once on a fresh endpoint where the current
 * one is registered with other keys.
 *
 * @returns The VAPID key the subscription is bound to.
 */
export async function subscribeDevice(
  inbox: PwaNotifications,
  registration: ServiceWorkerRegistration,
): Promise<Uint8Array> {
  const keys = await inbox.prepare();
  const subscription = await heldOrNewSubscription(registration, keys.vapidPublicKey);
  try {
    await inbox.set(await sealSubscription(subscription, keys.transportPublicKey));
    return keys.vapidPublicKey;
  } catch (error) {
    if (!(error instanceof EndpointInUseError)) throw error;
  }

  // A fresh prepare follows: the transport key the refused call was sealed to is spent.
  return subscribeFresh(inbox, registration, subscription);
}

/**
 * Replaces the push subscription `registration` holds with a fresh endpoint,
 * and registers it for the session behind `inbox`.
 *
 * @returns The VAPID key the subscription is bound to.
 */
export async function resubscribeDevice(
  inbox: PwaNotifications,
  registration: ServiceWorkerRegistration,
): Promise<Uint8Array> {
  const held = await registration.pushManager.getSubscription();
  return subscribeFresh(inbox, registration, held);
}

/**
 * Unsubscribes `held`, subscribes `registration` anew, and registers the new
 * endpoint. Keys come first, so `held` survives where they cannot be had.
 */
async function subscribeFresh(
  inbox: PwaNotifications,
  registration: ServiceWorkerRegistration,
  held: PushSubscription | null,
): Promise<Uint8Array> {
  const keys = await inbox.prepare();
  await held?.unsubscribe();
  const replacement = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: bytesOf(keys.vapidPublicKey),
  });
  await inbox.set(await sealSubscription(replacement, keys.transportPublicKey));
  return keys.vapidPublicKey;
}

/**
 * Where the VAPID key a subscribe bound this origin's push subscription to is
 * kept. A database of its own, apart from the session state a sign-out clears
 * and readable from the service worker, so it outlives every sign-in.
 */
const VAPID_KEY_DB = { dbName: 'auth-client-notifications', storeName: 'ic-keyval' };
const VAPID_KEY = 'vapid-public-key';

/**
 * The VAPID key `AuthClient.subscribeToNotifications` last bound this origin's push
 * subscription to, or `undefined` where it never ran here or the key cannot be
 * read.
 */
export async function savedVapidKey(): Promise<Uint8Array | undefined> {
  try {
    const db = await IdbKeyVal.create(VAPID_KEY_DB);
    const saved = await db.get<Uint8Array>(VAPID_KEY);
    return saved === null ? undefined : new Uint8Array(saved);
  } catch {
    return undefined;
  }
}

/** Records `vapidPublicKey` as the one this origin's push subscription is bound to. */
export async function saveVapidKey(vapidPublicKey: Uint8Array): Promise<void> {
  const db = await IdbKeyVal.create(VAPID_KEY_DB);
  await db.set(VAPID_KEY, vapidPublicKey);
}

/** Internet Identity's page that claims a same-device link from Safari. */
const SAME_DEVICE_LINK_PATH = '/ios-installed-app';

const LINK_KEY_ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' } as const;

const fromBase64Url = (value: string | undefined): Uint8Array => {
  if (value === undefined) throw new Error('The link key is missing a coordinate');
  const standard = value.replace(/-/g, '+').replace(/_/g, '/');
  return fromBase64(standard.padEnd(Math.ceil(standard.length / 4) * 4, '='));
};

const toBase64Url = (bytes: Uint8Array): string =>
  toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/**
 * Mints a one-shot P-256 key, registers its public half for the session behind
 * `inbox`, and answers the URL of Internet Identity's page that claims the link
 * from Safari with it.
 *
 * The private half travels in the fragment, as `d`, `x` and `y` of its JWK one
 * after the other, as Internet Identity's own install link carries its key: a
 * fragment is never sent to the gateway.
 */
export async function prepareSameDeviceLinkUrl(
  inbox: PwaNotifications,
  identityProviderOrigin: string,
): Promise<string> {
  const keyPair = (await crypto.subtle.generateKey(LINK_KEY_ALGORITHM, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  // Registered before the key is handed out, so a URL that exists is one Internet Identity waits for.
  await inbox.prepareSameDeviceLink(publicKey);
  const { d, x, y } = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const key = toBase64Url(concat(fromBase64Url(d), fromBase64Url(x), fromBase64Url(y)));
  const url = new URL(SAME_DEVICE_LINK_PATH, identityProviderOrigin);
  url.hash = new URLSearchParams({ key }).toString();
  return url.href;
}
