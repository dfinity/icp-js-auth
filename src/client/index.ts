/**
 * @module api/client
 */

export * from './auth-client.js';
export {
  APP_PENDING_SLOT,
  APP_SLOT,
  type Credential,
  type CredentialStorage,
  PENDING_SLOT,
  SESSION_SLOT,
  slotsFor,
} from './credential-storage.js';
export { DB_VERSION, type DBCreateOptions, IdbKeyVal } from './db.js';
export { IdbCredentialStorage } from './idb-credential-storage.js';
export * from './idle-manager.js';
export { LocalCredentialStorage } from './local-credential-storage.js';
export { MemoryCredentialStorage } from './memory-credential-storage.js';
export {
  LocalStateStorage,
  MemoryStateStorage,
  type SessionState,
  type StateStorage,
} from './state-storage.js';
