import { Actor, AnonymousIdentity, HttpAgent, type HttpAgentOptions } from '@icp-sdk/core/agent';
import type { IDL } from '@icp-sdk/core/candid';
import type { Principal } from '@icp-sdk/core/principal';

/**
 * Whether the organization domain a client was built with can be signed in with.
 *
 * - `checking`: Internet Identity has not answered yet.
 * - `available`: the domain resolves to a usable SSO configuration. `name` is
 *   the label the organization publishes, for a "Continue with Acme" button.
 * - `invalid`: the value is not a domain with an optional port, so no check is
 *   made and a retry cannot help. The user has to change what they typed.
 * - `unavailable`: the domain publishes no usable configuration, or fetching
 *   it is failing. While `retryAfter` is in the future Internet Identity will
 *   not fetch again, so a retry before then gets the same answer; without it,
 *   a retry cannot help.
 */
export type SsoStatus =
  | { state: 'checking' }
  | { state: 'available'; name?: string }
  | { state: 'invalid' }
  | { state: 'unavailable'; retryAfter?: Date };

type CandidSsoDomainStatus =
  | { Available: { name: [] | [string] } }
  | { Pending: null }
  | { Unavailable: { retry_after: [] | [bigint] } };

/** The two Internet Identity methods an SSO domain check calls. */
export interface SsoDomainService {
  app_sso_domain_check(domain: string): Promise<void>;
  app_sso_domain_status(domain: string): Promise<CandidSsoDomainStatus>;
}

/**
 * Written out for the same reason as the session methods in `session-minter.ts`:
 * this package carries no Internet Identity declarations.
 */
const idlFactory: IDL.InterfaceFactory = ({ IDL }) => {
  const Timestamp = IDL.Nat64;
  const Status = IDL.Variant({
    Available: IDL.Record({ name: IDL.Opt(IDL.Text) }),
    Pending: IDL.Null,
    Unavailable: IDL.Record({ retry_after: IDL.Opt(Timestamp) }),
  });
  return IDL.Service({
    app_sso_domain_check: IDL.Func([IDL.Text], [], []),
    app_sso_domain_status: IDL.Func([IDL.Text], [Status], ['query']),
  });
};

/**
 * Builds the service an SSO domain check calls, as the anonymous caller: the
 * check runs before anyone has signed in.
 */
export async function createSsoDomainService(options: {
  canisterId: Principal;
  agentOptions?: Omit<HttpAgentOptions, 'identity'>;
}): Promise<SsoDomainService> {
  const agent = await HttpAgent.create({
    ...options.agentOptions,
    // Last, so no agent option can make the check call as someone.
    identity: new AnonymousIdentity(),
  });
  return Actor.createActor<SsoDomainService>(idlFactory, {
    agent,
    canisterId: options.canisterId,
  });
}

/** How long a new client waits before its first call, so one discarded while the user types never calls. */
export const SSO_CHECK_DELAY_MS = 300;

/** The first and the longest wait between two status reads. */
export const SSO_POLL_MIN_MS = 500;
export const SSO_POLL_MAX_MS = 2_000;

/**
 * How long a check may read `Pending` before it is started again. Matches the
 * age at which Internet Identity treats a fetch as abandoned.
 */
export const SSO_RECHECK_AFTER_MS = 120_000;

const CHECKING: SsoStatus = Object.freeze({ state: 'checking' });
const INVALID: SsoStatus = Object.freeze({ state: 'invalid' });

const NANOS_PER_MILLI = 1_000_000n;

function fromCandid(status: CandidSsoDomainStatus): SsoStatus | undefined {
  if ('Available' in status) {
    const name = status.Available.name[0];
    return name === undefined ? { state: 'available' } : { state: 'available', name };
  }
  if ('Unavailable' in status) {
    const retryAfterNs = status.Unavailable.retry_after[0];
    return retryAfterNs === undefined
      ? { state: 'unavailable' }
      : { state: 'unavailable', retryAfter: new Date(Number(retryAfterNs / NANOS_PER_MILLI)) };
  }
  // Pending: the fetch is still running, which is what `checking` already says.
  return undefined;
}

function sameStatus(a: SsoStatus, b: SsoStatus): boolean {
  if (a.state !== b.state) return false;
  if (a.state === 'available' && b.state === 'available') return a.name === b.name;
  if (a.state === 'unavailable' && b.state === 'unavailable') {
    return a.retryAfter?.getTime() === b.retryAfter?.getTime();
  }
  return true;
}

/**
 * Asks Internet Identity whether one SSO domain can be signed in with, and holds
 * the answer.
 *
 * One update starts the fetch, then the status is read with a query until it is
 * final: a query needs no consensus, so polling it is cheap where polling an
 * update is not. A read that fails is retried at the next interval, so a check
 * ends only on an answer from Internet Identity, or on {@link dispose}.
 */
export class SsoStatusChecker {
  readonly #domain: string | undefined;
  readonly #createService: () => Promise<SsoDomainService>;
  readonly #onChange: () => void;
  #service: Promise<SsoDomainService> | undefined;
  #status: SsoStatus;
  #timer: ReturnType<typeof setTimeout> | undefined;
  // Bumped by every start and by dispose, so a run that was replaced drops its
  // late answers instead of overwriting a newer one.
  #run = 0;
  #disposed = false;

  /**
   * @param domain - The normalized domain, or `undefined` for a value that is
   *   not one, which is `invalid` from the start and never checked.
   * @param createService - Builds the service on the first call.
   * @param onChange - Called after the status changes.
   */
  constructor(
    domain: string | undefined,
    createService: () => Promise<SsoDomainService>,
    onChange: () => void,
  ) {
    this.#domain = domain;
    this.#createService = createService;
    this.#onChange = onChange;
    this.#status = domain === undefined ? INVALID : CHECKING;
    if (domain !== undefined) this.#start(SSO_CHECK_DELAY_MS);
  }

  /** The current answer. The same object until it changes. */
  get status(): SsoStatus {
    return this.#status;
  }

  /** Checks again. Does nothing for an `invalid` domain, or once disposed. */
  refresh(): void {
    if (this.#domain === undefined || this.#disposed) return;
    this.#set(CHECKING);
    this.#start(0);
  }

  /** Stops checking. A call already sent is not recalled; its answer is dropped. */
  dispose(): void {
    this.#disposed = true;
    this.#run += 1;
    clearTimeout(this.#timer);
    this.#timer = undefined;
  }

  #start(delayMs: number): void {
    this.#run += 1;
    const run = this.#run;
    clearTimeout(this.#timer);
    this.#timer = setTimeout(() => {
      void this.#check(run);
    }, delayMs);
  }

  #isCurrent(run: number): boolean {
    return run === this.#run && !this.#disposed;
  }

  async #check(run: number): Promise<void> {
    const domain = this.#domain;
    if (domain === undefined || !this.#isCurrent(run)) return;
    const checkedAt = Date.now();
    try {
      const service = await this.#serviceFor();
      if (!this.#isCurrent(run)) return;
      await service.app_sso_domain_check(domain);
    } catch {
      // The reads below still see whatever Internet Identity has, and a check
      // that never started is started again after `SSO_RECHECK_AFTER_MS`.
    }
    await this.#poll(run, domain, checkedAt, SSO_POLL_MIN_MS);
  }

  async #poll(run: number, domain: string, checkedAt: number, nextDelayMs: number): Promise<void> {
    if (!this.#isCurrent(run)) return;
    let answer: SsoStatus | undefined;
    try {
      const service = await this.#serviceFor();
      if (!this.#isCurrent(run)) return;
      answer = fromCandid(await service.app_sso_domain_status(domain));
    } catch {
      answer = undefined;
    }
    if (!this.#isCurrent(run)) return;
    if (answer !== undefined) {
      this.#set(answer);
      return;
    }
    if (Date.now() - checkedAt >= SSO_RECHECK_AFTER_MS) {
      this.#timer = setTimeout(() => {
        void this.#check(run);
      }, nextDelayMs);
      return;
    }
    this.#timer = setTimeout(() => {
      void this.#poll(run, domain, checkedAt, Math.min(nextDelayMs * 2, SSO_POLL_MAX_MS));
    }, nextDelayMs);
  }

  #serviceFor(): Promise<SsoDomainService> {
    if (this.#service === undefined) {
      const created = this.#createService();
      this.#service = created;
      // A service that could not be built is built again on the next call.
      created.catch(() => {
        if (this.#service === created) this.#service = undefined;
      });
    }
    return this.#service;
  }

  #set(next: SsoStatus): void {
    if (sameStatus(this.#status, next)) return;
    this.#status = next;
    this.#onChange();
  }
}
