import { Actor, HttpAgent, type HttpAgentOptions, type SignIdentity } from '@icp-sdk/core/agent';
import type { IDL } from '@icp-sdk/core/candid';
import { type DelegationChain, DelegationIdentity } from '@icp-sdk/core/identity';
import type { Principal } from '@icp-sdk/core/principal';
import type { Signer } from '@icp-sdk/signer';
import { SessionGoneError } from './app-delegation-source.js';
import { InteractionRequiredError } from './session-delegation.js';
import { assertChainReaches } from './session-minter.js';

/**
 * The method Internet Identity answers with the user's decision about being
 * notified. Named for its provider because a JSON-RPC method travels over a
 * transport shared with other signers, unlike a canister method.
 */
const NOTIFICATION_CONSENT_METHOD = 'ii_notification_consent';

/** The code Internet Identity denies a `prompt: 'none'` request with. */
const INTERACTION_REQUIRED_CODE = 3002;

/** JSON-RPC's own code for a method the receiver does not implement. */
const METHOD_NOT_FOUND_CODE = -32601;

/**
 * Whether the user has allowed this application to notify them.
 *
 * A record rather than a bare boolean, mirroring what the canister answers: a
 * second fact about the decision can then be reported without a breaking change
 * to anything that already reads `granted`.
 */
export interface NotificationConsentStatus {
  granted: boolean;
}

/**
 * Thrown where the identity provider does not send notifications at all.
 *
 * Its own error because its remedy is its own: there is nothing to retry and no
 * ceremony to run, so an application hides the control rather than reporting a
 * failure to the user. A deployment either carries the feature or does not.
 */
export class NotificationsUnsupportedError extends Error {
  constructor(message = 'This Internet Identity does not send notifications') {
    super(message);
    this.name = 'NotificationsUnsupportedError';
  }
}

/**
 * Asks the user, through the identity provider, whether this application may
 * notify them, and registers the browser for delivery where they agree.
 *
 * A refusal is an answer: it comes back as `granted: false` rather than as an
 * error, because the user decided and the application has something to render.
 *
 * @param signer - The channel to the identity provider.
 * @param derivationOrigin - The origin the account is derived for, where the
 *   application signs in under one other than its own.
 * @returns What the provider recorded, read back rather than reported from the
 *   screen.
 * @throws {InteractionRequiredError} Where the request asked not to render.
 * @throws {NotificationsUnsupportedError} Where the provider does not notify.
 */
export async function requestNotificationConsent(
  signer: Signer,
  derivationOrigin?: string,
): Promise<NotificationConsentStatus> {
  const response = await signer.sendRequest({
    jsonrpc: '2.0' as const,
    id: globalThis.crypto.randomUUID(),
    method: NOTIFICATION_CONSENT_METHOD,
    // Every member is optional, so an application with nothing to pass sends an
    // empty object rather than no `params` at all.
    params: derivationOrigin === undefined ? {} : { icrc95DerivationOrigin: derivationOrigin },
  });

  if ('error' in response) {
    if (response.error.code === METHOD_NOT_FOUND_CODE) {
      throw new NotificationsUnsupportedError(response.error.message);
    }
    if (response.error.code === INTERACTION_REQUIRED_CODE) {
      throw new InteractionRequiredError(response.error.message);
    }
    throw new Error(response.error.message);
  }

  const result = response.result as Record<string, unknown> | undefined;
  if (typeof result?.granted !== 'boolean') {
    throw new Error('Invalid response: missing granted');
  }
  return { granted: result.granted };
}

/** What the canister answers either consent call with. */
type NotificationConsentError = { NoSuchSession: null } | { InternalCanisterError: string };
type Result<T> = { Ok: T } | { Err: NotificationConsentError };

/** The two Internet Identity methods an application makes about its own consent. */
export interface NotificationConsentService {
  app_notification_consent_status(): Promise<Result<{ is_granted: boolean }>>;
  app_revoke_notification_consent(): Promise<Result<null>>;
}

/**
 * Written out for the same reason as the session methods in `session-minter.ts`:
 * this package carries no Internet Identity declarations.
 */
const idlFactory: IDL.InterfaceFactory = ({ IDL }) => {
  const ConsentError = IDL.Variant({
    NoSuchSession: IDL.Null,
    InternalCanisterError: IDL.Text,
  });
  const Status = IDL.Record({ is_granted: IDL.Bool });
  return IDL.Service({
    app_notification_consent_status: IDL.Func(
      [],
      [IDL.Variant({ Ok: Status, Err: ConsentError })],
      ['query'],
    ),
    app_revoke_notification_consent: IDL.Func(
      [],
      [IDL.Variant({ Ok: IDL.Null, Err: ConsentError })],
      [],
    ),
  });
};

/**
 * Unwraps a canister result, turning the one terminal error into
 * {@link SessionGoneError} and the other into a plain failure.
 */
const unwrap = <T>(result: Result<T>, failed: string): T => {
  if ('Ok' in result) return result.Ok;
  if ('NoSuchSession' in result.Err) throw new SessionGoneError();
  // A candid variant, so interpolating it directly renders "[object Object]" and
  // throws away the canister's own explanation of what went wrong.
  const detail = result.Err.InternalCanisterError;
  throw new Error(`${failed}${detail === '' ? '' : `: ${detail}`}`);
};

export interface NotificationConsentOptions {
  /** The key the session chain delegates to. Signs the calls made here. */
  sessionKey: SignIdentity;

  /** The chain proving those calls come from the session. Restricted to II. */
  sessionChain: DelegationChain;

  /** The canister these calls go to. */
  canisterId: Principal;

  /**
   * Options for the agent making them. `identity` is not among them: the agent
   * signs as the session, which is what both calls are authorised by.
   */
  agentOptions?: Omit<HttpAgentOptions, 'identity'>;
}

/** Reads and withdraws an application's consent, at the Internet Identity canister. */
export class NotificationConsent {
  readonly #service: NotificationConsentService;

  private constructor(service: NotificationConsentService) {
    this.#service = service;
  }

  /**
   * Builds the calls as the session.
   *
   * As the session and not as the application: Internet Identity authorises both
   * methods by the principal the session signs with, which is the one that mints
   * app delegations rather than any of the ones minted from it.
   */
  static async create(options: NotificationConsentOptions): Promise<NotificationConsent> {
    const { canisterId } = options;
    assertChainReaches(options.sessionChain, canisterId);
    const agent = await HttpAgent.create({
      ...options.agentOptions,
      // Last, so no agent option can replace the session these calls are made as.
      identity: DelegationIdentity.fromDelegation(options.sessionKey, options.sessionChain),
    });
    return new NotificationConsent(
      Actor.createActor<NotificationConsentService>(idlFactory, { agent, canisterId }),
    );
  }

  /**
   * Whether this application may notify the signed-in user.
   *
   * A query, so the answer is uncertified: it is what a control is painted from,
   * not something to rest a decision on.
   */
  async status(): Promise<NotificationConsentStatus> {
    const status = unwrap(
      await this.#service.app_notification_consent_status(),
      'Internet Identity could not report this notification consent',
    );
    return { granted: status.is_granted };
  }

  /**
   * Withdraws this application's consent to notify the signed-in user.
   *
   * Idempotent at the canister: consent that is already withdrawn is `Ok`, because
   * the caller wanted it gone and it is gone. What comes back as an error is the
   * canister failing to write, and it is raised rather than dropped — an
   * application that told a user it had turned notifications off should be able to
   * find out that it had not.
   */
  async revoke(): Promise<void> {
    unwrap(
      await this.#service.app_revoke_notification_consent(),
      'Internet Identity could not withdraw this notification consent',
    );
  }
}
