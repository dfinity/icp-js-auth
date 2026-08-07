/**
 * @module api/client
 */

export * from '../shared-session/storage.js';
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
export * from './sync-storage.js';
