import { describe, it } from 'vitest';
import { AuthClient } from '../../src/client/auth-client.ts';
import { IdbStorage } from '../../src/client/storage.ts';
import { SyncCookieStorage, SyncLocalStorage } from '../../src/client/sync-storage.ts';
import { SharedSessionStorage } from '../../src/shared-session/storage.ts';

const HUB = { url: 'https://auth.example.com/hub.html' };
const DERIVATION_ORIGIN = 'https://auth.example.com';

describe('SharedSessionStorage options', () => {
  it('requires a derivation origin', () => {
    new SharedSessionStorage({ hub: HUB, derivationOrigin: DERIVATION_ORIGIN });
    new SharedSessionStorage({
      hub: { ...HUB, timeout: 5_000 },
      derivationOrigin: new URL(DERIVATION_ORIGIN),
    });
    // @ts-expect-error a shared store without a shared derivation origin would
    // give each origin a different principal from the same key.
    new SharedSessionStorage({ hub: HUB });
  });
});

describe('AuthClientCreateOptions', () => {
  it('takes a shared session as its storage', () => {
    new AuthClient({
      storage: new SharedSessionStorage({ hub: HUB, derivationOrigin: DERIVATION_ORIGIN }),
      syncStorage: new SyncCookieStorage({ domain: 'example.com', namespace: 'auth.example.com' }),
      derivationOrigin: DERIVATION_ORIGIN,
    });
  });

  it('leaves the existing options unconstrained', () => {
    new AuthClient();
    new AuthClient({ storage: new IdbStorage() });
    new AuthClient({ syncStorage: new SyncLocalStorage() });
    new AuthClient({ derivationOrigin: DERIVATION_ORIGIN });
    new AuthClient({ keyType: 'Ed25519', transport: 'redirect', openIdProvider: 'google' });
  });
});
