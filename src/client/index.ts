/**
 * @module api/client
 */

export { type AppDelegationSource, SessionGoneError } from './app-delegation-source.js';
export * from './auth-client.js';
export type { Credential, CredentialStorage } from './credential-storage.js';
export { DB_VERSION, type DBCreateOptions, IdbKeyVal } from './db.js';
export { watchActivity, watchForeground } from './foreground-refresh.js';
export { IdbCredentialStorage } from './idb-credential-storage.js';
export { LocalCredentialStorage } from './local-credential-storage.js';
export { MemoryCredentialStorage } from './memory-credential-storage.js';
export { requestSessionDelegation } from './session-delegation.js';
export { SessionIdentity, type SessionIdentityOptions } from './session-identity.js';
export { SessionMinter, type SessionMinterOptions } from './session-minter.js';
export {
  LocalStateStorage,
  MemoryStateStorage,
  type SessionState,
  type StateStorage,
} from './state-storage.js';
