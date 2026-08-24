/**
 * @module api/client
 */

export { type AppDelegationSource, SessionGoneError } from './app-delegation-source.js';
export * from './auth-client.js';
export { type DBCreateOptions, IdbKeyVal } from './db.js';
export { IdbIdentityStorage } from './idb-identity-storage.js';
export type { IdentityStorage } from './identity-storage.js';
export * from './idle-manager.js';
export { LocalIdentityStorage } from './local-identity-storage.js';
export { LocalSessionStorage } from './local-session-storage.js';
export { SessionIdentity, type SessionIdentityOptions } from './session-identity.js';
export type { Session, SessionStorage } from './session-storage.js';
export {
  type AuthClientStorage,
  IdbStorage,
  KEY_STORAGE_DELEGATION,
  KEY_STORAGE_KEY,
  LocalStorage,
} from './storage.js';
