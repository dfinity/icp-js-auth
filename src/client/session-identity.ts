import type { DerEncodedPublicKey, HttpAgentRequest, SignIdentity } from '@icp-sdk/core/agent';
import { DelegationChain, DelegationIdentity } from '@icp-sdk/core/identity';
import { type AppDelegationSource, SessionGoneError } from './app-delegation-source.js';

/**
 * How much life an app delegation needs left to be handed to a caller. Covers a
 * request's flight time, because the delegation has to still be valid when the
 * replica verifies the request it was attached to.
 */
const BLOCK_MARGIN_MS = 10_000;

/**
 * When a replacement is minted. Covers one mint and nothing more: minting early
 * discards the rest of a delegation's life, so an active session consumes
 * lifetime at `ttl / (ttl - threshold)` and every second here costs update calls
 * on every active session. A refresh is scheduled for this moment rather than
 * waiting for a request to arrive inside the window, which is what keeps it small.
 */
const PRE_MINT_THRESHOLD_MS = 15_000;

const expiresAtMs = (chain: DelegationChain): number =>
  Number(
    chain.delegations.reduce(
      (soonest, { delegation }) =>
        delegation.expiration < soonest ? delegation.expiration : soonest,
      chain.delegations[0]?.delegation.expiration ?? 0n,
    ) / 1_000_000n,
  );

const sameKey = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, i) => byte === b[i]);

export interface SessionIdentityOptions {
  /** Signs the app's own calls. Held in memory, never persisted. */
  appKey: SignIdentity;

  /** The account's key, which every app delegation is rooted at. */
  accountKey: DerEncodedPublicKey;

  /** When the session itself ends. Nothing is minted past this. */
  sessionExpiresAtMs: number;

  source: AppDelegationSource;

  /**
   * Called once when the session turns out to be gone, so the client can drop
   * what it stored and tell its subscribers. Ending a session is the client's to
   * do; this only reports it.
   */
  onSessionGone: () => void;
}

/**
 * An identity whose delegation is short-lived and replaced under the caller.
 *
 * It extends {@link DelegationIdentity} so anything already accepting one
 * accepts this, and the delegation it presents is a normal app delegation. What
 * differs is that it replaces that delegation as it ages, which is why an agent
 * can hold this object for hours: an agent keeps whatever identity it was given,
 * so a snapshot of one delegation would sign with it until it expired.
 */
export class SessionIdentity extends DelegationIdentity {
  readonly #appKey: SignIdentity;
  readonly #source: AppDelegationSource;
  readonly #onSessionGone: () => void;
  readonly #sessionExpiresAtMs: number;

  #current: DelegationChain | undefined;
  #inFlight: Promise<DelegationChain> | undefined;
  #currentSignedARequest = false;
  #scheduled: ReturnType<typeof setTimeout> | undefined;
  #reportedGone = false;

  constructor(options: SessionIdentityOptions) {
    // The account's key is the root of every app delegation, so an empty chain
    // rooted at it answers getPublicKey() and getPrincipal() before the first
    // mint. A restored session can therefore say who is signed in without one.
    super(options.appKey, DelegationChain.fromDelegations([], options.accountKey));
    this.#appKey = options.appKey;
    this.#source = options.source;
    this.#onSessionGone = options.onSessionGone;
    this.#sessionExpiresAtMs = options.sessionExpiresAtMs;
  }

  override getDelegation(): DelegationChain {
    return this.#current ?? super.getDelegation();
  }

  override async transformRequest(request: HttpAgentRequest): Promise<unknown> {
    const chain = await this.#usable();
    this.#currentSignedARequest = true;
    return DelegationIdentity.fromDelegation(this.#appKey, chain).transformRequest(request);
  }

  /**
   * Mint now if one is due, and stay silent if it fails.
   *
   * For a caller that knows the moment is a good one, such as a tab coming back
   * to the foreground. The caller says when; this still decides whether.
   */
  async refresh(): Promise<void> {
    if (this.#current && this.#msLeft(this.#current) > PRE_MINT_THRESHOLD_MS) return;
    await this.#mint().catch(() => undefined);
  }

  /** Drops the scheduled refresh. */
  dispose(): void {
    clearTimeout(this.#scheduled);
    this.#scheduled = undefined;
  }

  #msLeft(chain: DelegationChain): number {
    return expiresAtMs(chain) - Date.now();
  }

  async #usable(): Promise<DelegationChain> {
    const current = this.#current;
    if (current) {
      const left = this.#msLeft(current);
      if (left > PRE_MINT_THRESHOLD_MS) return current;
      if (left > BLOCK_MARGIN_MS) {
        // Enough life to serve this request while a replacement is on its way.
        void this.#mint().catch(() => undefined);
        return current;
      }
    }
    return this.#mint();
  }

  #mint(): Promise<DelegationChain> {
    this.#inFlight ??= this.#mintOnce().finally(() => {
      this.#inFlight = undefined;
    });
    return this.#inFlight;
  }

  async #mintOnce(): Promise<DelegationChain> {
    // A delegation lasts min(its ttl, what remains of the session), so minting
    // against an almost finished session returns one already too short to use,
    // and refreshing on the delegation alone would mint without end.
    if (this.#sessionExpiresAtMs - Date.now() <= BLOCK_MARGIN_MS) {
      this.#reportGone();
      throw new SessionGoneError('The session has expired');
    }

    let chain: DelegationChain;
    try {
      chain = await this.#source.mint(this.#appKey.getPublicKey().toDer());
    } catch (error) {
      if (error instanceof SessionGoneError) this.#reportGone();
      throw error;
    }

    const expected = super.getDelegation().publicKey;
    if (!sameKey(chain.publicKey, expected)) {
      throw new Error('The minted delegation is rooted at another account');
    }

    this.#adopt(chain);
    return chain;
  }

  #adopt(chain: DelegationChain): void {
    this.#current = chain;
    this.#currentSignedARequest = false;
    this.#schedule(chain);
  }

  #schedule(chain: DelegationChain): void {
    clearTimeout(this.#scheduled);
    const delay = this.#msLeft(chain) - PRE_MINT_THRESHOLD_MS;
    if (delay <= 0) return;

    this.#scheduled = setTimeout(() => {
      // Only refresh a delegation something used. Each delegation earns the next
      // refresh and no more, so an application that goes quiet refreshes once
      // and then lets its delegation lapse rather than for as long as a tab is open.
      if (this.#currentSignedARequest) void this.#mint().catch(() => undefined);
    }, delay);

    // Never hold a Node process open for a refresh nobody is waiting on.
    (this.#scheduled as { unref?: () => void }).unref?.();
  }

  #reportGone(): void {
    if (this.#reportedGone) return;
    this.#reportedGone = true;
    this.dispose();
    this.#onSessionGone();
  }
}
