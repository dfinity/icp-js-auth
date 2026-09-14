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
