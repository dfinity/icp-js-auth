/**
 * Runs work while holding a named lock, where the environment has one.
 *
 * Its own module because the Web Locks API is a browser thing and `AuthClient`
 * runs outside a browser too. Where it is missing the work simply runs, which is
 * what makes the lock something to rely on for how much this costs and never for
 * whether it works.
 *
 * Two properties matter here, and a timeout could give neither. Tabs that reach
 * the lock at the same moment queue rather than proceeding together, which is what
 * removes a double-mint rather than narrowing the window for one. And a browser
 * releases a lock when the context holding it goes away, so a tab closed mid-mint
 * lets the next one proceed without anything deciding how long to wait for it.
 * @param name - Lock name. Shared by every tab of the origin.
 * @param run - The work to run while holding it.
 */
export function withLock<T>(name: string, run: () => Promise<T>): Promise<T> {
  const locks = globalThis.navigator?.locks;
  if (!locks) return run();
  return locks.request(name, run) as Promise<T>;
}
