/**
 * Every name one client writes under, and the one thing that knows the whole set.
 *
 * Its own module rather than living beside the credential store or the state
 * store, because it belongs to neither: the credentials and the state of a
 * sign-in are named from one namespace, and a list that sat in either file would
 * have to reach across to the other.
 */

/**
 * The bare names, before a namespace is applied.
 *
 * One list, so a name cannot be added to some of the places that need it and
 * missed in others. It was two lists and a hand-written mapping, and the state
 * record was left out of the namespacing for exactly that reason.
 */
const SLOT_NAMES = {
  /** The session's key and the chain issued to it. */
  session: 'session',

  /**
   * Where a sign-in ceremony keeps its key until it returns.
   *
   * Its own name rather than {@link SLOT_NAMES.session}, so a ceremony that is
   * cancelled or never comes back cannot take a working session with it.
   */
  sessionPending: 'session-pending',

  /** The key an application signs with, and its delegation. */
  app: 'app',

  /**
   * Where a ceremony keeps the credential it minted until its session is stored.
   *
   * The store reaches every tab of the origin, so writing to the app name during
   * a ceremony — or clearing it first — would change what those tabs act with
   * before the sign-in has succeeded. This is promoted instead, once there is a
   * session behind it.
   */
  appPending: 'app-pending',

  /**
   * The record of who is signed in here and until when.
   *
   * Not a credential slot, and named here anyway: a namespace that moved the
   * credentials and left this fixed would give two clients their own keys and one
   * shared answer to who is signed in.
   */
  state: 'ic-session-state',
} as const;

/**
 * What separates a namespace from the name it prefixes.
 *
 * A cross-origin contract rather than a detail: a sibling subdomain reads the
 * state record by name, so both sides have to agree on this byte.
 */
const NAMESPACE_SEPARATOR = ':';

/** Every name a client writes under, with its namespace already applied. */
export type Slots = Record<keyof typeof SLOT_NAMES, string>;

/**
 * The names one client writes under, prefixed where a namespace is set.
 *
 * Assigned in one place rather than defaulted by each store: implementations
 * choosing their own is what produced three colliding slots in the arrangement
 * this replaces, and one assigner cannot collide with itself. A namespace moves
 * all of them at once, so an application running two clients under one origin
 * separates them with one string rather than renaming some and missing others.
 * @param namespace - Prefix for every name, or `undefined` for the bare ones.
 */
export function slotsFor(namespace?: string): Slots {
  const prefix = namespace === undefined ? '' : `${namespace}${NAMESPACE_SEPARATOR}`;
  return Object.fromEntries(
    Object.entries(SLOT_NAMES).map(([key, name]) => [key, `${prefix}${name}`]),
  ) as Slots;
}
