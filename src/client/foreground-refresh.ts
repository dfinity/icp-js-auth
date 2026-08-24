/**
 * Calls back when the page is shown or the window regains focus.
 *
 * Its own module because it is the one part of the session machinery that needs a
 * DOM. `AuthClient` runs outside a browser too, so nothing else may assume these
 * APIs exist: where they do not, {@link watchForeground} returns `undefined` and
 * hooks nothing.
 *
 * A backgrounded tab has its timers throttled, so a session's scheduled refresh
 * may not run and its delegation lapses while nobody is looking. Coming back to
 * the tab happens a second or two before the user's next click, which is room
 * enough to mint in. Whether a mint is actually due is not decided here.
 * @param onForeground - Invoked when the page becomes visible or regains focus.
 * @returns A function that unhooks the listeners, or `undefined` where there is
 *   no DOM to hook.
 */
export function watchForeground(onForeground: () => void): (() => void) | undefined {
  if (typeof document === 'undefined' || typeof globalThis.addEventListener !== 'function') {
    return undefined;
  }

  const onVisible = (): void => {
    if (document.visibilityState === 'visible') onForeground();
  };

  document.addEventListener('visibilitychange', onVisible);
  // `focus` catches two visible windows side by side, where moving between them
  // is not a visibility change. `pageshow` catches a page restored from the
  // back-forward cache, which resumes with timers that never ran.
  globalThis.addEventListener('focus', onForeground);
  globalThis.addEventListener('pageshow', onForeground);

  return () => {
    document.removeEventListener('visibilitychange', onVisible);
    globalThis.removeEventListener('focus', onForeground);
    globalThis.removeEventListener('pageshow', onForeground);
  };
}
