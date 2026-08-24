import type { DerEncodedPublicKey, HttpAgentRequest, SignIdentity } from '@icp-sdk/core/agent';
import { DelegationChain, DelegationIdentity } from '@icp-sdk/core/identity';
import {
  type AppCredential,
  type AppDelegationSource,
  SessionGoneError,
} from './app-delegation-source.js';

/**
 * How much life a delegation needs left to be handed to a caller. Covers a
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

/** The leaf of a chain: the key it authorises. */
const delegatesTo = (chain: DelegationChain): Uint8Array | undefined =>
  chain.delegations[chain.delegations.length - 1]?.delegation.pubkey;

export interface SessionIdentityOptions {
  /** The account's key, which every app delegation is rooted at. */
  accountKey: DerEncodedPublicKey;

  /** When the session itself ends. Nothing is minted past this. */
  sessionExpiresAtMs: number;

  source: AppDelegationSource;

  /**
   * Makes the key a mint gets a delegation for. A fresh one each time, because a
   * key and its delegation expire together and a key outliving one is worthless.
   */
  newKey: () => Promise<SignIdentity>;

  /**
   * A credential already obtained for this session, adopted if it fits.
   *
   * Signing in mints before it resolves, and a tab opening may be handed one by
   * another tab, so either way the identity can start with one rather than
   * minting on its first request. Checked like any other, since one of these may
   * have come from somewhere else.
   */
  initial?: AppCredential;

  /**
   * Runs a mint while holding whatever serialises mints across tabs of an origin.
   *
   * Defaults to running it directly, which is one tab's worth of behaviour and
   * the whole of it where nothing can serialise.
   */
  withLock?: <T>(run: () => Promise<T>) => Promise<T>;

  /**
   * Called with each credential this identity mints, so a client can offer it to
   * other tabs. Not called for one that arrived from elsewhere, since passing
   * that on again would only go round in circles.
   */
  onMinted?: (credential: AppCredential) => void;

  /**
   * Called once when the session turns out to be gone, so the client can drop
   * what it holds and tell its subscribers. Ending a session is the client's to
   * do; this only reports it.
   */
  onSessionGone: () => void;
}

/**
 * An identity whose credential is short-lived and replaced under the caller.
 *
 * It extends {@link DelegationIdentity} so anything already accepting one accepts
 * this, and what it presents is an ordinary app delegation. What differs is that
 * the key and delegation it signs with are replaced as they age, which is why an
 * agent can hold this object for hours: an agent keeps whatever identity it was
 * given, so a snapshot of one credential would sign with it until it expired.
 *
 * A rotation is invisible to the holder. The principal comes from the account's
 * key rather than from whatever is current, and a request is signed and its
 * delegation attached in the same act, so what is already in flight carries a
 * matching pair however soon the next one arrives.
 */
export class SessionIdentity extends DelegationIdentity {
  readonly #source: AppDelegationSource;
  readonly #newKey: () => Promise<SignIdentity>;
  readonly #onSessionGone: () => void;
  readonly #withLock: <T>(run: () => Promise<T>) => Promise<T>;
  readonly #onMinted: ((credential: AppCredential) => void) | undefined;
  readonly #sessionExpiresAtMs: number;
  /** Reached by the base class's `sign`, so rotating does not change the object. */
  readonly #held: { current?: AppCredential };

  #inFlight: Promise<AppCredential> | undefined;
  #currentSignedARequest = false;
  #scheduled: ReturnType<typeof setTimeout> | undefined;
  #reportedGone = false;

  constructor(options: SessionIdentityOptions) {
    const held: { current?: AppCredential } = {};
    // The base signs through this, so what it holds can be replaced without the
    // object an application is holding changing. The account's key is the root of
    // every app delegation, so an empty chain rooted at it answers getPublicKey()
    // and getPrincipal() before anything is minted.
    super(
      {
        sign: (blob) => {
          const key = held.current?.key;
          if (!key) throw new Error('This identity holds no delegation yet');
          return key.sign(blob);
        },
      },
      DelegationChain.fromDelegations([], options.accountKey),
    );
    this.#held = held;
    this.#source = options.source;
    this.#newKey = options.newKey;
    this.#onSessionGone = options.onSessionGone;
    this.#withLock = options.withLock ?? ((run) => run());
    this.#onMinted = options.onMinted;
    this.#sessionExpiresAtMs = options.sessionExpiresAtMs;
    // Through adopt(), because one of these may have come from another tab.
    if (options.initial) this.adopt(options.initial);
  }

  override getDelegation(): DelegationChain {
    return this.#held.current?.chain ?? super.getDelegation();
  }

  override async transformRequest(request: HttpAgentRequest): Promise<unknown> {
    const credential = await this.#usable();
    this.#currentSignedARequest = true;
    return DelegationIdentity.fromDelegation(credential.key, credential.chain).transformRequest(
      request,
    );
  }

  /**
   * Takes a credential obtained elsewhere, such as by another tab of this origin.
   *
   * Refused unless it is rooted at this account and authorises the key it arrived
   * with, so a mismatched pair is discarded where the mistake was made rather
   * than failing later at a boundary node.
   * @returns whether it was adopted.
   */
  adopt(credential: AppCredential): boolean {
    if (!this.#isForThisSession(credential)) return false;
    this.#adopt(credential);
    return true;
  }

  /**
   * Mint now if one is due, and stay silent if it fails.
   *
   * For a caller that knows the moment is a good one, such as a tab coming back
   * to the foreground. The caller says when; this still decides whether.
   */
  async refresh(): Promise<void> {
    const current = this.#held.current;
    if (current && this.#msLeft(current.chain) > PRE_MINT_THRESHOLD_MS) return;
    await this.#mint().catch(() => undefined);
  }

  /** Drops the scheduled refresh. */
  dispose(): void {
    clearTimeout(this.#scheduled);
    this.#scheduled = undefined;
  }

  #isForThisSession({ key, chain }: AppCredential): boolean {
    const leaf = delegatesTo(chain);
    return (
      sameKey(chain.publicKey, super.getDelegation().publicKey) &&
      leaf !== undefined &&
      sameKey(new Uint8Array(leaf), new Uint8Array(key.getPublicKey().toDer()))
    );
  }

  #msLeft(chain: DelegationChain): number {
    return expiresAtMs(chain) - Date.now();
  }

  async #usable(): Promise<AppCredential> {
    const current = this.#held.current;
    if (current) {
      const left = this.#msLeft(current.chain);
      if (left > PRE_MINT_THRESHOLD_MS) return current;
      if (left > BLOCK_MARGIN_MS) {
        // Enough life to serve this request while a replacement is on its way.
        void this.#mint().catch(() => undefined);
        return current;
      }
    }
    return this.#mint();
  }

  #mint(): Promise<AppCredential> {
    this.#inFlight ??= this.#withLock(() => this.#mintOnce()).finally(() => {
      this.#inFlight = undefined;
    });
    return this.#inFlight;
  }

  async #mintOnce(): Promise<AppCredential> {
    // Inside the lock now, which may have been held by a tab that minted while
    // this one queued. Look again before spending a call.
    const held = this.#held.current;
    if (held && this.#msLeft(held.chain) > PRE_MINT_THRESHOLD_MS) return held;

    // A delegation lasts min(its ttl, what remains of the session), so minting
    // against an almost finished session returns one already too short to use,
    // and refreshing on the delegation alone would mint without end.
    if (this.#sessionExpiresAtMs - Date.now() <= BLOCK_MARGIN_MS) {
      this.#reportGone();
      throw new SessionGoneError('The session has expired');
    }

    const key = await this.#newKey();
    let chain: DelegationChain;
    try {
      chain = await this.#source.mint(key.getPublicKey().toDer());
    } catch (error) {
      if (error instanceof SessionGoneError) this.#reportGone();
      throw error;
    }

    const credential = { key, chain };
    if (!this.#isForThisSession(credential)) {
      throw new Error('The minted delegation is not for this account and key');
    }

    this.#adopt(credential);
    this.#onMinted?.(credential);
    return credential;
  }

  #adopt(credential: AppCredential): void {
    this.#held.current = credential;
    this.#currentSignedARequest = false;
    this.#schedule(credential.chain);
  }

  #schedule(chain: DelegationChain): void {
    clearTimeout(this.#scheduled);
    const delay = this.#msLeft(chain) - PRE_MINT_THRESHOLD_MS;
    if (delay <= 0) return;

    this.#scheduled = setTimeout(() => {
      // Only refresh a credential something used. Each one earns the next refresh
      // and no more, so an application that goes quiet lets its delegation lapse
      // rather than refreshing for as long as a tab is open.
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
