/**
 * Runs `mint` while holding a named lock, where the environment has one.
 *
 * The lock is the library coordinating with itself rather than anything a store
 * provides, so a store answers only whether another tab can read it and needs to
 * know nothing about the Web Locks API.
 *
 * Where there is no lock — an older browser, or a store no other tab reads —
 * `mint` runs straight away and every tab mints for itself. That costs calls and
 * never correctness: coordination may only ever suppress a mint, never be
 * required for one.
 *
 * `mint` is handed a signal that fires when the lock is taken away by
 * {@link stealMintLock}. It is the only thing a mint can act on, because a call
 * already sent cannot be recalled: the mint runs to completion and the signal is
 * what tells it to throw away the result rather than store it.
 * @param name - The lock to hold, or `null` to run without one.
 * @param mint - The work to serialise, taking the signal described above.
 */
export function withMintLock<T>(
  name: string | null,
  mint: (stolen: AbortSignal) => Promise<T>,
): Promise<T> {
  const locks = globalThis.navigator?.locks;
  if (name === null || locks === undefined) {
    // Nothing can take a lock that was never held, so the signal never fires.
    return mint(new AbortController().signal);
  }

  const stolen = new AbortController();
  const held = locks.request(name, () => mint(stolen.signal)) as Promise<T>;

  // A steal releases this tab's lock and rejects this promise, in this document.
  // That rejection is the only notice another tab's sign-out can deliver, so it
  // is turned into the signal `mint` was given rather than being surfaced: the
  // mint decides what to do about it, and the caller sees whatever it returns.
  held.catch(() => stolen.abort());
  return held;
}

/**
 * Takes the lock away from whoever holds it, without waiting for them.
 *
 * What signing out does. Queueing would make a sign-out the user asked for wait
 * on a canister call in another tab, and a mint that finished afterwards would
 * write a credential into the slot the sign-out had just cleared.
 * @param name - The lock to take, or `null` where none is held.
 */
export async function stealMintLock(name: string | null): Promise<void> {
  const locks = globalThis.navigator?.locks;
  if (name === null || locks === undefined) return;

  // Granted at once, and released at once: holding it would only make the caller
  // the next thing a queued mint waits for.
  await locks.request(name, { steal: true }, () => undefined).catch(() => undefined);
}

/**
 * A lock this holder keeps until it gives it up, and a signal for losing it.
 *
 * Unlike {@link withMintLock}, what needs guarding here is not one call but a
 * span — a ceremony is several calls and then several writes — so the lock is
 * held across it and released by the holder rather than by a callback returning.
 */
export interface HeldLock {
  /** Fires when someone else takes this lock away. */
  readonly stolen: AbortSignal;

  /**
   * Gives the lock up.
   *
   * Idempotent, and safe to call after it was stolen: releasing a lock this
   * holder no longer has does nothing.
   */
  release(): void;
}

/**
 * Takes a lock away from whoever holds it and keeps it until released.
 *
 * Taken rather than queued for, like {@link stealMintLock} and for the same
 * reason: the newer intent is the one to honour. A user who presses sign in
 * again means the second press, and an origin has one signer window, so the two
 * cannot both proceed anyway. The incumbent finds out through {@link
 * HeldLock.stolen} and throws its result away instead of writing it.
 *
 * Where there is no lock — an older browser, or a caller that passes `null`
 * because nothing else could be holding one — the result never reports a steal
 * and releasing does nothing. That costs coordination, never correctness:
 * coordination may only ever suppress work, never be required for it.
 * @param name - The lock to take, or `null` to take none.
 */
export function stealLock(name: string | null): HeldLock {
  const stolen = new AbortController();
  const locks = globalThis.navigator?.locks;
  if (name === null || locks === undefined) {
    return { stolen: stolen.signal, release: () => {} };
  }

  // The callback holds the lock for as long as what it returns is pending, so
  // this is what `release` settles. A steal rejects the `request` promise in this
  // document, which is the only notice the platform gives.
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  void locks
    .request(name, { steal: true }, () => held)
    .catch((error: unknown) => {
      // Only a steal, which arrives as an `AbortError`. A request can fail for
      // reasons that are nothing to do with another holder — a frame going away
      // takes its callback with it — and reporting one of those as a steal would
      // tell the caller its work was superseded when nothing had superseded it.
      if (error instanceof DOMException && error.name === 'AbortError') {
        stolen.abort();
      }
    });

  return { stolen: stolen.signal, release: () => release() };
}
