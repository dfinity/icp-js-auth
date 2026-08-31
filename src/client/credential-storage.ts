import type { SignIdentity } from '@icp-sdk/core/agent';
import type { DelegationChain } from '@icp-sdk/core/identity';

/** Where the session's key and the chain issued to it are kept. */
export const SESSION_SLOT = 'session';

/** Where the key an application signs with is kept, with its delegation. */
export const APP_SLOT = 'app';

/**
 * Where a ceremony keeps the credential it minted until its session is stored.
 *
 * The store reaches every tab of the origin, so writing to {@link APP_SLOT}
 * during a ceremony — or clearing it first — would change what those tabs act
 * with before the sign-in has succeeded. This is promoted instead, once there is
 * a session behind it.
 */
export const APP_PENDING_SLOT = 'app-pending';

/**
 * Where a sign-in ceremony keeps its key until it returns.
 *
 * Its own slot rather than {@link SESSION_SLOT}, so a ceremony that is cancelled
 * or never comes back cannot take a working session with it.
 */
export const PENDING_SLOT = 'session-pending';

/** Where the state of a sign-in is kept, when nothing names it otherwise. */
export const STATE_KEY = 'ic-session-state';

/**
 * Every name one client writes under, prefixed where a namespace is set.
 *
 * Assigned in one place rather than defaulted by each store: implementations
 * choosing their own is what produced three colliding slots in the arrangement
 * this replaces, and one assigner cannot collide with itself. A namespace moves
 * all of them at once, so an application running two clients under one origin
 * separates them with one string rather than renaming some and missing others.
 *
 * The state record is named here too, and not because it is a credential slot —
 * it is not. It is named here because this is the only place that knows the whole
 * set, and a namespace that moved the credentials while leaving the record fixed
 * would give two clients separate keys and one shared answer to who is signed in.
 * @param namespace - Prefix for every name, or `undefined` for the bare ones.
 */
export function slotsFor(namespace?: string): {
  session: string;
  app: string;
  pending: string;
  appPending: string;
  state: string;
} {
  const prefix = namespace === undefined ? '' : `${namespace}:`;
  return {
    session: `${prefix}${SESSION_SLOT}`,
    app: `${prefix}${APP_SLOT}`,
    pending: `${prefix}${PENDING_SLOT}`,
    appPending: `${prefix}${APP_PENDING_SLOT}`,
    state: `${prefix}${STATE_KEY}`,
  };
}

/**
 * An identity, and the delegation that authorises it.
 *
 * The two are one record because a delegation is issued to a key: held apart
 * they can disagree, and every reader then has to decide what a chain whose key
 * is missing means. Stored together, the half that would be dangerous — a chain
 * with no key to sign for it — cannot be written down at all.
 */
export interface Credential<T extends SignIdentity = SignIdentity> {
  identity: T;

  /**
   * Absent only while a ceremony is in flight, under {@link PENDING_SLOT}: there
   * is a key, and no delegation for it yet.
   */
  chain?: DelegationChain;
}

/**
 * Holds the material a client acts with, a credential per slot.
 *
 * Asynchronous, because using a credential means making a call and a
 * non-extractable key needs a store that can hold one. What a page renders on is
 * the state rather than this, so nothing here has to answer without awaiting.
 *
 * A store knows two things about its medium that the library cannot infer, and
 * declares both.
 */
export interface CredentialStorage<T extends SignIdentity = SignIdentity> {
  /** Whether another tab of this origin reads what this writes. */
  readonly shared: boolean;

  /** Whether what this writes survives the document being torn down. */
  readonly durable: boolean;

  /**
   * A fresh identity of this store's own type, not persisted.
   *
   * Generation belongs to the store because the medium decides the key type: one
   * that has to serialise needs a key whose private bytes are readable, and one
   * that does not should not have them. Kept together so an application cannot
   * pair a non-extractable key with a store that cannot hold one and find out at
   * runtime.
   */
  create(): Promise<T>;

  /** The credential stored under `slot`, or `null` where there is none. */
  get(slot: string): Promise<Credential<T> | null>;

  set(slot: string, credential: Credential<T>): Promise<void>;

  remove(slot: string): Promise<void>;
}
