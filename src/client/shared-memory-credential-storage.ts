import { DelegationChain, ECDSAKeyIdentity } from '@icp-sdk/core/identity';
import type { Credential, CredentialStorage } from './credential-storage.js';

/** The channel and lock prefix every instance agrees on by default. */
export const DEFAULT_SHARED_MEMORY_NAME = 'ic-credentials';

/** What one slot travels as: a key handle, and the chain as JSON. */
interface WireCredential {
  slot: string;
  keyPair: CryptoKeyPair;
  chain?: string;
}

/** A write, replicated to every tab as it happens. */
interface Put extends WireCredential {
  kind: 'put';
}

/** A removal, replicated the same way. */
interface Drop {
  kind: 'drop';
  slot: string;
}

/** A starting instance asking whoever is already running for what it holds. */
interface Ask {
  kind: 'ask';
}

/** Everything one instance holds, in answer to an {@link Ask}. */
interface Offer {
  kind: 'offer';
  entries: WireCredential[];
}

type Message = Put | Drop | Ask | Offer;

// A channel reaches one origin, so a malformed message is our own code — a tab
// running a different version through a deploy, or an application posting on the
// name. Checked anyway, because the predicate is what tells the reader a payload
// is there.
const isMessage = (value: unknown): value is Message => {
  if (typeof value !== 'object' || value === null || !('kind' in value)) return false;
  const message = value as { kind: unknown; slot?: unknown; entries?: unknown };
  switch (message.kind) {
    case 'ask':
      return true;
    case 'drop':
      return typeof message.slot === 'string';
    case 'put':
      return typeof message.slot === 'string' && 'keyPair' in message;
    case 'offer':
      return Array.isArray(message.entries);
    default:
      return false;
  }
};

/**
 * Credentials in memory, replicated to the other tabs of this origin.
 *
 * For an environment with no durable medium — a browser with IndexedDB and
 * `localStorage` both unavailable, or an application that has decided nothing may
 * reach disk — where every tab minting for itself is still worth avoiding.
 *
 * Every write is broadcast and every instance applies what it receives, so a
 * steady-state read is local and immediate: the medium is a `Map`, and the channel
 * is what keeps the Maps agreeing. A `CryptoKeyPair` survives a structured clone
 * as a handle that signs and cannot be exported, so what crosses is usable
 * without key material having been sent.
 *
 * Nothing survives the document, which is what `durable` says. What that costs is
 * the last tab of an origin closing: the credentials go with it, and the next load
 * signs in again.
 * @see implements {@link CredentialStorage}
 */
export class SharedMemoryCredentialStorage implements CredentialStorage<ECDSAKeyIdentity> {
  public readonly shared = true;
  public readonly durable = false;

  readonly #name: string;
  readonly #channel: BroadcastChannel | undefined;

  // On the instance and never on the module, so two clients on one page keep
  // their own replicas and no state carries between tests in one process.
  readonly #replica = new Map<string, Credential<ECDSAKeyIdentity>>();

  // Held for this instance's life under a name only this instance uses, so a peer
  // can wait for the grant that means this one is gone. The browser releases it
  // when the document is torn down, which is the signal no message could carry.
  readonly #id = crypto.randomUUID();
  #releasePresence: (() => void) | undefined;

  #announceOffer: (() => void) | undefined;

  // Applying an incoming record is asynchronous, because a key handle and a chain
  // have to be rebuilt from what crossed. Queued so they land in the order they
  // arrived: a put applied after the drop that followed it would resurrect a slot
  // its owner had already cleared.
  #applying: Promise<void> = Promise.resolve();

  /**
   * Resolves once there is nothing left to wait for: a peer has answered, or
   * every peer that existed when this instance started has gone.
   *
   * Reads await it, so the first one after a cold start sees what the other tabs
   * hold rather than a miss. There is no deadline in it — waiting ends on a lock
   * grant, and a lone instance waits not at all because there is no peer to hold
   * one.
   */
  readonly #synced: Promise<void>;

  /**
   * @param options - The channel and lock prefix the tabs of this origin share.
   */
  constructor(options?: { name?: string }) {
    this.#name = options?.name ?? DEFAULT_SHARED_MEMORY_NAME;
    this.#channel =
      typeof BroadcastChannel === 'undefined' ? undefined : new BroadcastChannel(this.#name);
    this.#channel?.addEventListener('message', (event) => this.#receive(event.data));
    this.#synced = this.#openReplica();
  }

  /** Stops replicating and lets go of the name a peer waits on. */
  public close(): void {
    this.#channel?.close();
    this.#releasePresence?.();
    this.#releasePresence = undefined;
  }

  public create(): Promise<ECDSAKeyIdentity> {
    return ECDSAKeyIdentity.generate({ extractable: false });
  }

  public async get(slot: string): Promise<Credential<ECDSAKeyIdentity> | null> {
    await this.#synced;
    // A read reflects everything received, not everything that has finished being
    // rebuilt: applying is asynchronous, so a message already in hand would
    // otherwise read as a miss and cost the caller a credential it had.
    await this.#applying;
    return this.#replica.get(slot) ?? null;
  }

  public async set(slot: string, credential: Credential<ECDSAKeyIdentity>): Promise<void> {
    this.#replica.set(slot, credential);
    this.#post({ kind: 'put', ...this.#toWire(slot, credential) });
  }

  public async remove(slot: string): Promise<void> {
    this.#replica.delete(slot);
    this.#post({ kind: 'drop', slot });
  }

  #presenceName(id: string): string {
    return `${this.#name}:alive:${id}`;
  }

  /**
   * Takes this instance's presence lock, then waits for the peers that already
   * had one — asking them for what they hold.
   */
  async #openReplica(): Promise<void> {
    const locks = globalThis.navigator?.locks;
    if (locks === undefined || this.#channel === undefined) {
      // Nothing can be enumerated and nothing can answer, so waiting could only
      // cost a load. Every instance is alone, which is calls and not correctness.
      return;
    }

    const peers = await this.#claimPresence(locks);
    if (peers.length === 0) return;

    const answered = new Promise<void>((resolve) => {
      this.#announceOffer = resolve;
    });

    this.#post({ kind: 'ask' });

    // A peer that answers ends the wait; a peer that dies without answering ends
    // it too, because its lock is granted the moment the browser releases it. So
    // the wait is bounded by the peers themselves rather than by a number.
    const goneEverywhere = Promise.all(
      peers.map((name) => locks.request(name, { mode: 'exclusive' }, () => undefined)),
    );
    await Promise.race([answered, goneEverywhere]);
  }

  /**
   * Enumerates the peers holding a presence lock, then takes this instance's own.
   *
   * In that order: a snapshot taken after would include this instance, and it
   * would then wait for a lock it holds itself and never be granted.
   */
  async #claimPresence(locks: LockManager): Promise<string[]> {
    const mine = this.#presenceName(this.#id);
    const prefix = `${this.#name}:alive:`;

    let peers: string[] = [];
    try {
      const snapshot = await locks.query();
      peers = (snapshot.held ?? [])
        .map((lock) => lock.name)
        .filter((name): name is string => name !== undefined && name !== mine)
        .filter((name) => name.startsWith(prefix));
    } catch {
      // query() is not everywhere, and a caller cannot act on its absence. With
      // no snapshot there is no peer to wait for, so this instance starts alone.
    }

    // Not awaited: the request resolves only when the lock is released, which is
    // when this instance is done with it.
    void locks
      .request(mine, { mode: 'exclusive' }, () => {
        return new Promise<void>((resolve) => {
          this.#releasePresence = resolve;
        });
      })
      .catch(() => undefined);

    return peers;
  }

  #receive(data: unknown): void {
    if (!isMessage(data)) return;

    if (data.kind === 'ask') {
      // Answered from what is queued as well as what has landed, so an instance
      // asked while still applying an earlier message does not describe a state
      // it is halfway out of.
      this.#enqueue(() => {
        const entries = [...this.#replica].map(([slot, credential]) =>
          this.#toWire(slot, credential),
        );
        // Answered even when empty, because the asker is waiting on an answer and
        // "I have nothing" is one. Staying silent would make it wait for this
        // instance to close.
        this.#post({ kind: 'offer', entries });
      });
      return;
    }

    this.#enqueue(async () => {
      switch (data.kind) {
        case 'offer':
          for (const entry of data.entries) await this.#apply(entry, { overwrite: false });
          // Last, so the answer is complete before anything waiting on it wakes.
          this.#announceOffer?.();
          this.#announceOffer = undefined;
          return;
        case 'put':
          await this.#apply(data, { overwrite: true });
          return;
        case 'drop':
          this.#replica.delete(data.slot);
          return;
      }
    });
  }

  #enqueue(work: () => void | Promise<void>): void {
    this.#applying = this.#applying.then(work).catch(() => undefined);
  }

  async #apply(entry: WireCredential, { overwrite }: { overwrite: boolean }): Promise<void> {
    // An offer answers a question asked before anything local was written, so it
    // fills gaps rather than replacing: a write that happened in the meantime is
    // this instance's own and newer than the snapshot being described.
    if (!overwrite && this.#replica.has(entry.slot)) return;

    try {
      const identity = await ECDSAKeyIdentity.fromKeyPair(entry.keyPair);
      const chain = entry.chain === undefined ? undefined : DelegationChain.fromJSON(entry.chain);
      this.#replica.set(entry.slot, { identity, chain });
    } catch {
      // A record from an incompatible version, or a handle this context cannot
      // adopt. Holding nothing lets the reader acquire again.
    }
  }

  #toWire(slot: string, credential: Credential<ECDSAKeyIdentity>): WireCredential {
    return {
      slot,
      keyPair: credential.identity.getKeyPair(),
      chain: credential.chain && JSON.stringify(credential.chain.toJSON()),
    };
  }

  #post(message: Message): void {
    try {
      this.#channel?.postMessage(message);
    } catch {
      // A closed channel, or a payload this browser will not clone. The write has
      // already landed in this instance's own replica, so the cost is a peer
      // missing it and minting for itself.
    }
  }
}
