import { Actor, HttpAgent } from '@icp-sdk/core/agent';
import type { IDL } from '@icp-sdk/core/candid';
import { DelegationIdentity } from '@icp-sdk/core/identity';
import type { Principal } from '@icp-sdk/core/principal';
import type { NotificationConsentOptions } from './notification-consent.js';
import { SessionGoneError } from './session/app-delegation-source.js';
import { assertChainReaches } from './session/session-minter.js';

/**
 * Whether this page runs as an installed web app rather than in a browser tab.
 *
 * iOS predates the display-mode query for Home Screen apps and reports them
 * through `navigator.standalone` instead, so both are asked.
 */
export function isInstalledApp(): boolean {
  if (globalThis.matchMedia?.('(display-mode: standalone)').matches === true) return true;
  const navigator = globalThis.navigator as (Navigator & { standalone?: boolean }) | undefined;
  return navigator?.standalone === true;
}

/** Why the service worker could not show a notification. */
export type NotShownReason = { PayloadUnreachable: null } | { PayloadRejected: null };

/** Why Internet Identity handed out no subscription keys. */
type PrepareError =
  | { NoSuchSession: null }
  | { NotificationsNotAllowed: null }
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

/** The Internet Identity methods an installed app's subscription is made of. */
export interface PwaNotificationService {
  app_prepare_pwa_webpush_subscription(): Promise<
    | { Ok: { vapid_public_key: Uint8Array; transport_public_key: Uint8Array } }
    | { Pending: null }
    | { Err: PrepareError }
  >;
  app_set_pwa_webpush_subscription(request: {
    subscription: [] | [SealedSubscription];
  }): Promise<{ Ok: null } | { Err: SubscriptionError }>;
  app_get_pwa_webpush_subscription_status(): Promise<
    { Ok: [] | [{ endpoint: string }] } | { Err: NotificationError }
  >;
  app_get_pwa_notification(request: {
    inbox_notification_id: bigint;
  }): Promise<{ Ok: { notification: [] | [PwaNotification] } } | { Err: NotificationError }>;
  app_remove_pwa_notification(request: {
    inbox_notification_id: bigint;
    not_shown: [] | [NotShownReason];
  }): Promise<{ Ok: Record<string, never> } | { Err: NotificationError }>;
}

/** Written out because this package carries no Internet Identity declarations. */
const idlFactory: IDL.InterfaceFactory = ({ IDL }) => {
  const PrepareError = IDL.Variant({
    NoSuchSession: IDL.Null,
    NotificationsNotAllowed: IDL.Null,
    InternalCanisterError: IDL.Text,
  });
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
      [],
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
        }),
      ],
      [IDL.Variant({ Ok: IDL.Null, Err: SubscriptionError })],
      [],
    ),
    app_get_pwa_webpush_subscription_status: IDL.Func(
      [],
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
        }),
      ],
      [IDL.Variant({ Ok: IDL.Record({}), Err: NotificationError })],
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

const unwrapSubscription = <T>(
  result: { Ok: T } | { Err: PrepareError | SubscriptionError },
): T => {
  if ('Ok' in result) return result.Ok;
  const error = result.Err;
  if ('NoSuchSession' in error) throw new SessionGoneError();
  if ('EndpointInUse' in error) throw new EndpointInUseError();
  if ('NotificationsNotAllowed' in error) {
    throw new Error('The user has not allowed this application to notify them');
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
 * the session.
 */
export class PwaNotifications {
  readonly #service: PwaNotificationService;

  private constructor(service: PwaNotificationService) {
    this.#service = service;
  }

  /** As the session, which is what Internet Identity reads the identity, browser and app from. */
  static async create(options: NotificationConsentOptions): Promise<PwaNotifications> {
    const { canisterId } = options;
    assertChainReaches(options.sessionChain, canisterId);
    const agent = await HttpAgent.create({
      ...options.agentOptions,
      identity: DelegationIdentity.fromDelegation(options.sessionKey, options.sessionChain),
    });
    return new PwaNotifications(
      Actor.createActor<PwaNotificationService>(idlFactory, { agent, canisterId }),
    );
  }

  /**
   * The keys the next subscribe needs, asked for again while Internet Identity
   * answers Pending: it is still fetching its VAPID key or drawing randomness.
   */
  async prepare(): Promise<SubscriptionKeys> {
    for (let attempt = 0; attempt < PREPARE_ATTEMPTS; attempt++) {
      if (attempt > 0) await wait(attempt * PREPARE_RETRY_STEP_MS);
      const response = await this.#service.app_prepare_pwa_webpush_subscription();
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
        subscription: subscription === null ? [] : [subscription],
      }),
    );
  }

  /**
   * The endpoint Internet Identity delivers to for this session's browser and
   * account, or `undefined` where it holds none for them.
   */
  async registeredEndpoint(): Promise<string | undefined> {
    const status = unwrapNotification(
      await this.#service.app_get_pwa_webpush_subscription_status(),
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
        inbox_notification_id: inboxNotificationId,
        not_shown: notShown === undefined ? [] : [notShown],
      }),
      'Internet Identity could not remove this notification',
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

  const browser = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
    'deriveBits',
  ]);
  const transportKey = new Uint8Array(await crypto.subtle.exportKey('raw', browser.publicKey));
  const theirs = await crypto.subtle.importKey(
    'raw',
    bytesOf(transportPublicKey),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );
  const shared = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: theirs },
    browser.privateKey,
    SHARED_SECRET_BITS,
  );
  const extracted = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);

  // The canister's key first and this one second, which is the order it rebuilds in.
  const info = concat(INFO_PREFIX, transportPublicKey, transportKey);
  const derive = (label: Uint8Array, bits: number): Promise<ArrayBuffer> =>
    crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new ArrayBuffer(0),
        info: bytesOf(concat(info, label)),
      },
      extracted,
      bits,
    );

  const key = await crypto.subtle.importKey(
    'raw',
    await derive(KEY_LABEL, AES_KEY_BITS),
    'AES-GCM',
    false,
    ['encrypt'],
  );
  const sealedAuth = new Uint8Array(
    await crypto.subtle.encrypt(
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
const subscribedWith = (subscription: PushSubscription, applicationServerKey: Uint8Array) => {
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
 * Subscribes `registration` with Internet Identity's VAPID key and registers the
 * subscription for the session behind `inbox`, retrying once on a fresh
 * endpoint where the current one is registered with other keys.
 */
export async function subscribeDevice(
  inbox: PwaNotifications,
  registration: ServiceWorkerRegistration,
): Promise<void> {
  const keys = await inbox.prepare();
  const subscription = await heldOrNewSubscription(registration, keys.vapidPublicKey);
  try {
    await inbox.set(await sealSubscription(subscription, keys.transportPublicKey));
    return;
  } catch (error) {
    if (!(error instanceof EndpointInUseError)) throw error;
  }

  await subscription.unsubscribe();
  // A fresh prepare: the transport key the refused call was sealed to is spent.
  const fresh = await inbox.prepare();
  const replacement = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: bytesOf(fresh.vapidPublicKey),
  });
  await inbox.set(await sealSubscription(replacement, fresh.transportPublicKey));
}
