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
    NoMatchingSession: IDL.Null,
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
    app_revoke_session: IDL.Func([], [], []),
  });
};

type AppSessionError = { NoMatchingSession: null } | { InternalCanisterError: string };
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
  app_revoke_session(): Promise<void>;
}

const isGone = (error: AppSessionError): boolean => 'NoMatchingSession' in error;

/**
 * Unwraps a canister result, turning the one terminal error into
 * {@link SessionGoneError} and everything else into a retryable failure.
 */
export const unwrapSessionResult = <T>(result: Result<T>): T => {
  if ('Ok' in result) return result.Ok;
  if (isGone(result.Err)) throw new SessionGoneError();
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

  async mint(appPublicKey: DerEncodedPublicKey): Promise<DelegationChain> {
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

  /**
   * Ends the session at the canister.
   *
   * The method returns nothing and has no error variant, so a session that was
   * already gone is not an error. The call itself can still fail the way any
   * update call can — an unreachable boundary node, a transport fault — and that
   * rejection is the caller's to decide about.
   */
  async revoke(): Promise<void> {
    await this.#service.app_revoke_session();
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
  // The signature covers whatever fields the canister set, and a delegation
  // carrying permissions cannot be represented by the chain type, so sending one
  // without it would fail verification at the boundary node with nothing to point
  // at. Read-only sessions are unsupported until the type carries the field.
  if (signed.delegation.permissions.length > 0) {
    throw new Error(
      'This session is read-only, which @icp-sdk/auth cannot act for yet: its delegations carry permissions that a delegation chain has no room for',
    );
  }

  return DelegationChain.fromDelegations(
    [
      {
        delegation: new Delegation(
          signed.delegation.pubkey,
          signed.delegation.expiration,
          signed.delegation.targets[0],
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
 * targets imposes nothing, so one restricting hop is what confines the key. The
 * chain Internet Identity issues is exactly that shape — the canister signs an
 * unrestricted hop to the provider's own key, and the provider's extension to
 * the application's key is the hop that names the canister.
 *
 * So what is refused is a chain no hop restricts, which the session key would
 * otherwise be able to sign any call with, and one whose restrictions do not
 * come out as this canister alone.
 */
export function assertChainReaches(chain: DelegationChain, canisterId: Principal): void {
  const hops = chain.delegations.map(({ delegation }) => delegation.targets);
  const restricting = hops.filter((hopTargets): hopTargets is Principal[] => hopTargets !== undefined);

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
