import { Actor, type DerEncodedPublicKey, HttpAgent, type SignIdentity } from '@icp-sdk/core/agent';
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
  const Delegation = IDL.Record({
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
          Ok: IDL.Record({ delegation: Delegation, signature: SessionKey }),
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
  throw new Error(`Internet Identity could not mint a delegation: ${result.Err}`);
};

export interface SessionMinterOptions {
  /** The key the session chain delegates to. Signs the calls made here. */
  sessionKey: SignIdentity;

  /** The chain proving those calls come from the session. Restricted to II. */
  sessionChain: DelegationChain;

  /**
   * Where to send the calls. The Internet Identity canister is served by the
   * gateway that serves its frontend, so this is the identity provider's origin.
   */
  host: string;

  /** Local replicas sign with a key an agent has to be told. */
  fetchRootKey?: boolean;
}

/**
 * Mints app delegations by asking the Internet Identity canister for one.
 *
 * The canister id is taken from the session chain's targets, which restrict that
 * chain to Internet Identity, so nothing has to be configured with it.
 */
export class SessionMinter implements AppDelegationSource {
  readonly #service: SessionService;

  private constructor(service: SessionService) {
    this.#service = service;
  }

  static async create(options: SessionMinterOptions): Promise<SessionMinter> {
    const canisterId = canisterFrom(options.sessionChain);
    const agent = await HttpAgent.create({
      host: options.host,
      identity: DelegationIdentity.fromDelegation(options.sessionKey, options.sessionChain),
      shouldFetchRootKey: options.fetchRootKey ?? false,
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

  /** Ends the session at the canister. Returns nothing and cannot fail. */
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

/** The one canister a session chain is allowed to reach. */
export function canisterFrom(chain: DelegationChain): Principal {
  const targets = chain.delegations.flatMap(({ delegation }) => delegation.targets ?? []);
  const [canisterId] = targets;
  if (!canisterId || targets.some((target) => target.compareTo(canisterId) !== 'eq')) {
    throw new Error('A session chain must be restricted to the Internet Identity canister');
  }
  return canisterId;
}
