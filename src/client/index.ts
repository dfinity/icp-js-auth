/**
 * @module api/client
 */

export * from './auth-client.js';
export type { Credential, CredentialStorage } from './credentials/credential-storage.js';
export { IdbCredentialStorage } from './credentials/idb-credential-storage.js';
export { LocalCredentialStorage } from './credentials/local-credential-storage.js';
export { MemoryCredentialStorage } from './credentials/memory-credential-storage.js';
export {
  DEFAULT_SHARED_MEMORY_NAME,
  SharedMemoryCredentialStorage,
} from './credentials/shared-memory-credential-storage.js';
export { DB_VERSION, type DBCreateOptions, IdbKeyVal } from './db.js';
export { watchActivity, watchForeground } from './foreground-refresh.js';
export {
  NotificationConsent,
  type NotificationConsentOptions,
  type NotificationConsentService,
  type NotificationConsentStatus,
  NotificationsUnsupportedError,
  requestNotificationConsent,
} from './notification-consent.js';
export { type AppDelegationSource, SessionGoneError } from './session/app-delegation-source.js';
export {
  InteractionRequiredError,
  requestSessionDelegation,
} from './session/session-delegation.js';
export { SessionIdentity, type SessionIdentityOptions } from './session/session-identity.js';
export { SessionMinter, type SessionMinterOptions } from './session/session-minter.js';
export type { SsoStatus } from './sso.js';
export {
  CookieStateStorage,
  type CookieStateStorageOptions,
} from './state/cookie-state-storage.js';
export { LocalStateStorage } from './state/local-state-storage.js';
export { MemoryStateStorage } from './state/memory-state-storage.js';
export type { SessionState, StateStorage } from './state/state-storage.js';
