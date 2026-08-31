/**
 * Calls back when the page is shown or the window regains focus.
 *
 * Its own module because it is the one part of the session machinery that needs a
 * DOM. `AuthClient` runs outside a browser too, so nothing else may assume these
 * APIs exist: where they do not, this and {@link watchActivity} return
 * `undefined` and hook nothing.
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
  // Every API this hooks, checked one at a time: a partial DOM polyfill can
  // define `document` without the event methods, and throwing there would
  // contradict the promise that this hooks nothing where there is no DOM.
  if (
    typeof document === 'undefined' ||
    typeof document.addEventListener !== 'function' ||
    typeof document.removeEventListener !== 'function' ||
    typeof globalThis.addEventListener !== 'function' ||
    typeof globalThis.removeEventListener !== 'function'
  ) {
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

// `pointerdown` covers a mouse, a finger and a pen in one, which is the only
// press event a phone reliably produces. The list the retired idle timer
// listened to, put to the opposite use: it ended a session on their absence,
// and they now keep one alive by their presence.
const ACTIVITY_EVENTS = ['pointerdown', 'mousedown', 'mousemove', 'keydown', 'touchstart', 'wheel'];

/**
 * Calls back when somebody is using the page.
 *
 * A user moving a mouse is very likely about to do something that needs a
 * delegation, so this is the same claim {@link watchForeground} makes — this
 * page is in front of a person right now — from the other direction. Whether a
 * mint is actually due is not decided here, and the identity's pre-mint
 * threshold is what keeps a resting hand from costing more than one mint per
 * refresh interval.
 *
 * It matters beyond saving the first request a mint: a session bounded by how
 * long it goes unminted would otherwise end under a user who is reading rather
 * than clicking.
 * @param onActivity - Invoked on any sign of use.
 * @returns A function that unhooks the listeners, or `undefined` where there is
 *   no DOM to hook.
 */
export function watchActivity(onActivity: () => void): (() => void) | undefined {
  if (
    typeof document === 'undefined' ||
    typeof document.addEventListener !== 'function' ||
    typeof document.removeEventListener !== 'function'
  ) {
    return undefined;
  }

  // Passive: these never call `preventDefault`, and saying so keeps a listener on
  // `mousemove` and `wheel` off the path that decides whether a scroll may start.
  for (const event of ACTIVITY_EVENTS) {
    document.addEventListener(event, onActivity, { passive: true });
  }

  return () => {
    for (const event of ACTIVITY_EVENTS) {
      document.removeEventListener(event, onActivity);
    }
  };
}
