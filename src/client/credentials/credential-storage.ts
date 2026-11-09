import type { SignIdentity } from '@icp-sdk/core/agent';
import type { DelegationChain } from '@icp-sdk/core/identity';

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
   * Absent only while a ceremony is in flight, under the session-pending slot: there
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
