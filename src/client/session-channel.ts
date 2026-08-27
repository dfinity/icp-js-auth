/**
 * The channel tabs of one origin use to agree on an app key and its delegation.
 *
 * Its own module because it is where a `BroadcastChannel` is assumed, and
 * `AuthClient` runs outside a browser too. Where there is none,
 * {@link openSessionChannel} returns `undefined` and every tab is simply alone,
 * which costs a mint each rather than being incorrect.
 *
 * A channel reaches the tabs of one origin and no further. A sibling subdomain is
 * a different origin, so what crosses between siblings is the hint cookie and
 * nothing else.
 */

/** Asks whoever is already running for a key to share. */
interface Ask {
  kind: 'ask';
}

/**
 * Answers an {@link Ask}.
 *
 * The key travels as a `CryptoKeyPair`, which survives a structured clone as a
 * handle that signs and cannot be exported, so no key material crosses. The chain
 * travels as JSON, because a `DelegationChain` is class instances that a
 * structured clone would flatten.
 */
interface Offer {
  kind: 'offer';
  keyPair: CryptoKeyPair;
  chainJson?: string;
}

export type SessionMessage = Ask | Offer;

export interface SessionChannel {
  post(message: SessionMessage): void;
  close(): void;
}

// A channel reaches one origin, so a malformed message is our own code — a tab
// running a different version during a deploy, or an application posting on the
// name. Checked anyway, because the predicate is what tells the caller the
// payload is there, and an offer without a key pair reaches the adopter as a
// rejection nothing catches.
const looksLikeMessage = (value: unknown): value is SessionMessage => {
  const message = value as SessionMessage | undefined;
  if (message?.kind === 'ask') return true;
  if (message?.kind !== 'offer') return false;
  const { keyPair, chainJson } = message;
  return (
    typeof keyPair === 'object' &&
    keyPair !== null &&
    'privateKey' in keyPair &&
    'publicKey' in keyPair &&
    (chainJson === undefined || typeof chainJson === 'string')
  );
};

/**
 * Opens the channel for an origin, or returns `undefined` where there is none.
 * @param name - Channel name. Separates clients that should not answer each
 *   other; `AuthClient` uses one name per origin, since an origin is one
 *   application with one storage configuration.
 * @param onMessage - Called for each message from another tab. A channel never
 *   delivers a tab its own messages.
 */
export function openSessionChannel(
  name: string,
  onMessage: (message: SessionMessage) => void,
): SessionChannel | undefined {
  if (typeof BroadcastChannel !== 'function') return undefined;

  const channel = new BroadcastChannel(name);
  channel.onmessage = (event: MessageEvent) => {
    if (looksLikeMessage(event.data)) onMessage(event.data);
  };

  return {
    post: (message) => {
      try {
        channel.postMessage(message);
      } catch {
        // A closed channel, or an environment that cannot carry what this holds.
        // Sharing is an optimisation, so failing to share is not a failure: every
        // tab still mints for itself.
      }
    },
    close: () => {
      channel.onmessage = null;
      channel.close();
    },
  };
}
