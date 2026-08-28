import type { DerEncodedPublicKey, HttpAgentRequest } from '@icp-sdk/core/agent';
import { DelegationChain, DelegationIdentity } from '@icp-sdk/core/identity';
import { type AppDelegationSource, SessionGoneError } from './app-delegation-source.js';
import { withMintLock } from './app-lock.js';
import { APP_SLOT, type Credential, type CredentialStorage } from './credential-storage.js';

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

/** A credential that is certainly whole: only a ceremony's slot holds a key alone. */
type Held = Required<Credential>;

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
   * Where the app credential is kept, and what makes the key a mint gets a
   * delegation for.
   *
   * The store is what every tab of the origin reads, so a delegation minted in
   * one is the delegation the others use.
   */
  storage: CredentialStorage;

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
  readonly #storage: CredentialStorage;
  readonly #onSessionGone: () => void;
  readonly #sessionExpiresAtMs: number;
  /** Reached by the base class's `sign`, so rotating does not change the object. */
  readonly #held: { current?: Held };

  #inFlight: Promise<Held> | undefined;
  #currentSignedARequest = false;
  #scheduled: ReturnType<typeof setTimeout> | undefined;
  #reportedGone = false;

  constructor(options: SessionIdentityOptions) {
    const held: { current?: Held } = {};
    // The base signs through this, so what it holds can be replaced without the
    // object an application is holding changing. The account's key is the root of
    // every app delegation, so an empty chain rooted at it answers getPublicKey()
    // and getPrincipal() before anything is minted.
    super(
      {
        sign: (blob) => {
          const key = held.current?.identity;
          if (!key) throw new Error('This identity holds no delegation yet');
          return key.sign(blob);
        },
      },
      DelegationChain.fromDelegations([], options.accountKey),
    );
    this.#held = held;
    this.#source = options.source;
    this.#storage = options.storage;
    this.#onSessionGone = options.onSessionGone;
    this.#sessionExpiresAtMs = options.sessionExpiresAtMs;
  }

  override getDelegation(): DelegationChain {
    return this.#held.current?.chain ?? super.getDelegation();
  }

  override async transformRequest(request: HttpAgentRequest): Promise<unknown> {
    const credential = await this.#usable();
    this.#currentSignedARequest = true;
    return DelegationIdentity.fromDelegation(
      credential.identity,
      credential.chain,
    ).transformRequest(request);
  }

  /**
   * Mint now if one is due, and stay silent if it fails.
   *
   * For a caller that knows the moment is a good one, such as a page load or a
   * tab coming back to the foreground. The caller says when; this still decides
   * whether, so a credential with plenty of life left costs nothing.
   */
  async refresh(): Promise<void> {
    const current = this.#held.current;
    // Held and healthy: nothing to do, and re-adopting it would reset the flag
    // that says it signed a request — which is what the scheduled refresh checks
    // before firing, so glancing at a tab would cancel its own rotation.
    if (current && this.#msLeft(current.chain) > PRE_MINT_THRESHOLD_MS) return;

    if (current === undefined) {
      // Nothing held yet, so what another tab left is worth having before minting.
      const stored = await this.#readStored();
      if (stored && this.#msLeft(stored.chain) > PRE_MINT_THRESHOLD_MS) {
        this.#adopt(stored);
        return;
      }
    }
    await this.#mint().catch(() => undefined);
  }

  /** Drops the scheduled refresh. */
  dispose(): void {
    clearTimeout(this.#scheduled);
    this.#scheduled = undefined;
  }

  /** The name of the lock a mint is serialised on, or `null` where none is worth taking. */
  get #lockName(): string | null {
    // A store no other tab can read has nothing another tab could adopt, so
    // serialising would spread the mints without preventing any of them.
    return this.#storage.shared ? APP_SLOT : null;
  }

  #isForThisSession({ identity, chain }: Held): boolean {
    const leaf = delegatesTo(chain);
    return (
      sameKey(chain.publicKey, super.getDelegation().publicKey) &&
      leaf !== undefined &&
      sameKey(new Uint8Array(leaf), new Uint8Array(identity.getPublicKey().toDer()))
    );
  }

  #msLeft(chain: DelegationChain): number {
    return expiresAtMs(chain) - Date.now();
  }

  /**
   * The stored credential, where there is one this session may use.
   *
   * Whatever another tab minted arrives this way: sharing is a read of the store
   * rather than a conversation, which works whether the other tabs are running,
   * frozen, or gone.
   */
  async #readStored(): Promise<Held | undefined> {
    const stored = await this.#storage.get(APP_SLOT).catch(() => null);
    if (!stored?.chain) return undefined;

    const credential = { identity: stored.identity, chain: stored.chain };
    if (!this.#isForThisSession(credential)) return undefined;
    return credential;
  }

  async #usable(): Promise<Held> {
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

  #mint(): Promise<Held> {
    this.#inFlight ??= this.#mintOnce().finally(() => {
      this.#inFlight = undefined;
    });
    return this.#inFlight;
  }

  async #mintOnce(): Promise<Held> {
    // A delegation lasts min(its ttl, what remains of the session), so minting
    // against an almost finished session returns one already too short to use,
    // and refreshing on the delegation alone would mint without end.
    if (this.#sessionExpiresAtMs - Date.now() <= BLOCK_MARGIN_MS) {
      this.#reportGone();
      throw new SessionGoneError('The session has expired');
    }

    return withMintLock(this.#lockName, async () => {
      // Read before minting, and adopt what is found. The lock alone would only
      // serialise: five tabs waking together would queue politely and then make
      // five calls one after another. This read is what turns serialising into
      // suppressing, and it is why the floor is one mint per origin rather than
      // one per tab.
      const stored = await this.#readStored();
      if (stored && this.#msLeft(stored.chain) > PRE_MINT_THRESHOLD_MS) {
        this.#adopt(stored);
        return stored;
      }

      const identity = await this.#storage.create();
      let chain: DelegationChain;
      try {
        chain = await this.#source.mint(identity.getPublicKey().toDer());
      } catch (error) {
        if (error instanceof SessionGoneError) this.#reportGone();
        throw error;
      }

      const credential = { identity, chain };
      if (!this.#isForThisSession(credential)) {
        throw new Error('The minted delegation is not for this account and key');
      }

      // A credential that cannot be written is still one this tab can use. The
      // cost of a failed write is that other tabs mint for themselves, which is
      // what they do without a lock at all — it is not a reason to fail the
      // request that is waiting on this.
      await this.#storage.set(APP_SLOT, credential).catch(() => undefined);
      this.#adopt(credential);
      return credential;
    });
  }

  #adopt(credential: Held): void {
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
