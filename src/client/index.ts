/**
 * @module api/client
 */

export * from './auth-client.js';
export { type DBCreateOptions, IdbKeyVal } from './db.js';
export * from './idle-manager.js';
export {
  type AuthClientStorage,
  IdbStorage,
  KEY_STORAGE_DELEGATION,
  KEY_STORAGE_KEY,
  LocalStorage,
} from './storage.js';
export {
  type AuthClientSyncStorage,
  type SessionHint,
  SyncCookieStorage,
  type SyncCookieStorageOptions,
  SyncLocalStorage,
} from './sync-storage.js';
