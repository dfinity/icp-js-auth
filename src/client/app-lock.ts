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
 * @param name - The lock to hold, or `null` to run without one.
 * @param mint - The work to serialise.
 */
export function withMintLock<T>(name: string | null, mint: () => Promise<T>): Promise<T> {
  const locks = globalThis.navigator?.locks;
  if (name === null || locks === undefined) return mint();
  return locks.request(name, mint) as Promise<T>;
}
