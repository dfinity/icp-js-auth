import {
  Actor,
  type DerEncodedPublicKey,
  HttpAgent,
  type HttpAgentOptions,
  type SignIdentity,
} from '@icp-sdk/core/agent';
import type { IDL } from '@icp-sdk/core/candid';
import { Delegation, DelegationChain, DelegationIdentity } from '@icp-sdk/core/identity';
import type { Principal } from '@icp-sdk/core/principal';
import { type AppDelegationSource, SessionGoneError } from './app-delegation-source.js';

/**
 * Just the three methods an app calls with a session chain. Written out rather
 * than generated because this package carries no Internet Identity declarations,
 * and generating them for three methods would mean carrying the whole interface.
 */
const idlFactory: IDL.InterfaceFactory = ({ IDL }) => {
  const SessionKey = IDL.Vec(IDL.Nat8);
  const Timestamp = IDL.Nat64;
  const AppSessionError = IDL.Variant({
    NoSuchSession: IDL.Null,
    NoSuchDelegation: IDL.Null,
    InternalCanisterError: IDL.Text,
  });
  const CandidDelegation = IDL.Record({
    pubkey: SessionKey,
    expiration: Timestamp,
    targets: IDL.Opt(IDL.Vec(IDL.Principal)),
    permissions: IDL.Opt(IDL.Text),
  });
  return IDL.Service({
    app_prepare_delegation: IDL.Func(
      [IDL.Record({ session_key: SessionKey })],
      [
        IDL.Variant({
          Ok: IDL.Record({ user_key: SessionKey, expiration: Timestamp }),
          Err: AppSessionError,
        }),
      ],
      [],
    ),
    app_get_delegation: IDL.Func(
      [IDL.Record({ session_key: SessionKey, expiration: Timestamp })],
      [
        IDL.Variant({
          Ok: IDL.Record({ delegation: CandidDelegation, signature: SessionKey }),
          Err: AppSessionError,
        }),
      ],
      ['query'],
    ),
    app_revoke_session: IDL.Func([], [IDL.Variant({ Ok: IDL.Null, Err: AppSessionError })], []),
  });
};

type AppSessionError =
  | { NoSuchSession: null }
  | { NoSuchDelegation: null }
  | { InternalCanisterError: string };
type Result<T> = { Ok: T } | { Err: AppSessionError };

interface SessionService {
  app_prepare_delegation(request: {
    session_key: Uint8Array;
  }): Promise<Result<{ user_key: Uint8Array; expiration: bigint }>>;
  app_get_delegation(request: { session_key: Uint8Array; expiration: bigint }): Promise<
    Result<{
      delegation: {
        pubkey: Uint8Array;
        expiration: bigint;
        targets: [] | [Principal[]];
        permissions: [] | [string];
      };
      signature: Uint8Array;
    }>
  >;
  app_revoke_session(): Promise<Result<null>>;
}

const isGone = (error: AppSessionError): boolean => 'NoSuchSession' in error;

/**
 * Raised when the canister signed nothing for the key and expiration asked for,
 * which means the expiration was not one `app_prepare_delegation` returned.
 *
 * Its own error because the remedy is its own: prepare again and use what comes
 * back. Signing in afresh is not it — the session is live, or the call would have
 * been refused for being no session at all.
 */
class NoSuchDelegationError extends Error {
  constructor() {
    super('Internet Identity signed no delegation for this key and expiration');
    this.name = 'NoSuchDelegationError';
  }
}

/**
 * Unwraps a canister result, turning the one terminal error into
 * {@link SessionGoneError}, the retryable one into
 * {@link NoSuchDelegationError}, and everything else into a plain failure.
 */
export const unwrapSessionResult = <T>(result: Result<T>): T => {
  if ('Ok' in result) return result.Ok;
  if (isGone(result.Err)) throw new SessionGoneError();
  if ('NoSuchDelegation' in result.Err) throw new NoSuchDelegationError();
  // A candid variant, so interpolating it directly renders "[object Object]" and
  // throws away the canister's own explanation of what went wrong.
  const detail = 'InternalCanisterError' in result.Err ? result.Err.InternalCanisterError : '';
  throw new Error(
    `Internet Identity could not mint a delegation${detail === '' ? '' : `: ${detail}`}`,
  );
};

export interface SessionMinterOptions {
  /** The key the session chain delegates to. Signs the calls made here. */
  sessionKey: SignIdentity;

  /** The chain proving those calls come from the session. Restricted to II. */
  sessionChain: DelegationChain;

  /** The canister these calls go to. */
  canisterId: Principal;

  /**
   * Options for the agent making them. `identity` is not among them: the agent
   * signs as the session, which is what a mint call rests on.
   */
  agentOptions?: Omit<HttpAgentOptions, 'identity'>;
}

/** Mints app delegations by asking the Internet Identity canister for one. */
export class SessionMinter implements AppDelegationSource {
  readonly #service: SessionService;

  private constructor(service: SessionService) {
    this.#service = service;
  }

  static async create(options: SessionMinterOptions): Promise<SessionMinter> {
    const { canisterId } = options;
    assertChainReaches(options.sessionChain, canisterId);
    const agent = await HttpAgent.create({
      ...options.agentOptions,
      // Last, so no agent option can replace the session these calls are made as.
      identity: DelegationIdentity.fromDelegation(options.sessionKey, options.sessionChain),
    });
    return new SessionMinter(Actor.createActor<SessionService>(idlFactory, { agent, canisterId }));
  }

  /**
   * Prepares and fetches an app delegation, once more if the fetch finds nothing
   * signed for what the prepare handed out.
   *
   * The pair is two calls, and only the first of them is an update: an expiration
   * the canister will not sign for is one this session no longer holds, and the
   * answer is to prepare again rather than to sign in again. Attempted a second
   * time and no further — a third would be pursuing something other than the race
   * this covers.
   */
  async mint(appPublicKey: DerEncodedPublicKey): Promise<DelegationChain> {
    try {
      return await this.#mintOnce(appPublicKey);
    } catch (error) {
      if (!(error instanceof NoSuchDelegationError)) throw error;
      return await this.#mintOnce(appPublicKey);
    }
  }

  /**
   * Ends the session at the canister.
   *
   * Idempotent at the canister: a session that is already gone is `Ok`, because
   * the caller wanted it gone and it is gone. What comes back as an error is the
   * canister failing to write, and it is raised rather than dropped — an
   * application that told a user it signed them out of their apps should be able
   * to find out that it did not. The call can also fail the way any update call
   * can, and that rejection is the caller's to decide about too.
   */
  async revoke(): Promise<void> {
    unwrapSessionResult(await this.#service.app_revoke_session());
  }

  async #mintOnce(appPublicKey: DerEncodedPublicKey): Promise<DelegationChain> {
    const prepared = unwrapSessionResult(
      await this.#service.app_prepare_delegation({ session_key: appPublicKey }),
    );

    const signed = unwrapSessionResult(
      await this.#service.app_get_delegation({
        session_key: appPublicKey,
        // Exactly what was prepared. A different value is a different signature.
        expiration: prepared.expiration,
      }),
    );

    return appDelegationChain(prepared.user_key, signed);
  }
}

/**
 * Assembles the one-hop chain an app signs its calls with, rooted at the
 * account's own key.
 */
export function appDelegationChain(
  userKey: Uint8Array,
  signed: {
    delegation: {
      pubkey: Uint8Array;
      expiration: bigint;
      targets: [] | [Principal[]];
      permissions: [] | [string];
    };
    signature: Uint8Array;
  },
): DelegationChain {
  return DelegationChain.fromDelegations(
    [
      {
        delegation: new Delegation(
          signed.delegation.pubkey,
          signed.delegation.expiration,
          signed.delegation.targets[0],
          signed.delegation.permissions[0],
        ),
        signature: signed.signature as DelegationChain['delegations'][number]['signature'],
      },
    ],
    userKey as DerEncodedPublicKey,
  );
}

/**
 * Refuses a chain that is not a session for `canisterId`.
 *
 * Targets restrict what the chain's final key may call, and the effective
 * restriction is the intersection of the hops that name any: a hop with no
 * targets imposes nothing, so one restricting hop is enough to confine the key.
 * Internet Identity names the canister on both of its hops — on the one the
 * canister signs to the provider's own key, and again on the provider's
 * extension to the application's key — and the intersection is what is checked,
 * so a hop that stopped naming it would still leave the chain confined by the
 * other.
 *
 * So what is refused is a chain no hop restricts, which the session key would
 * otherwise be able to sign any call with, and one whose restrictions do not
 * come out as this canister alone.
 */
export function assertChainReaches(chain: DelegationChain, canisterId: Principal): void {
  const hops = chain.delegations.map(({ delegation }) => delegation.targets);
  const restricting = hops.filter(
    (hopTargets): hopTargets is Principal[] => hopTargets !== undefined,
  );

  if (restricting.length === 0) {
    throw new Error(
      `A session chain must be restricted to ${canisterId.toText()}, but no hop of this one names any canister`,
    );
  }
  // An empty list names nothing rather than naming this canister, and a chain
  // that can call nothing is not a session either.
  const namingNothing = restricting.some((hopTargets) => hopTargets.length === 0);
  if (namingNothing) {
    throw new Error(
      `A session chain must be restricted to ${canisterId.toText()}, but a hop of this one names nothing`,
    );
  }
  const elsewhere = restricting
    .flat()
    .filter((target) => target.compareTo(canisterId) !== 'eq')
    .map((target) => target.toText());
  if (elsewhere.length > 0) {
    throw new Error(
      `A session chain must be restricted to ${canisterId.toText()}, but this one also names ${[...new Set(elsewhere)].join(', ')}`,
    );
  }
}
