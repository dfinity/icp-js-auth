import { describe, it } from 'vitest';
import { AuthClient } from '../../src/client/auth-client.ts';
import { IdbStorage } from '../../src/client/storage.ts';
import { SyncCookieStorage, SyncLocalStorage } from '../../src/client/sync-storage.ts';
import { SharedSessionStorage } from '../../src/shared-session/storage.ts';

const HUB_URL = 'https://auth.example.com/shared-session.html';
const DERIVATION_ORIGIN = 'https://auth.example.com';

describe('SharedSessionStorage options', () => {
  it('takes the hub url, and optionally a timeout', () => {
    new SharedSessionStorage({ url: HUB_URL });
    new SharedSessionStorage({ url: new URL(HUB_URL), timeout: 5_000 });
    // @ts-expect-error the hub's url is what identifies the shared session.
    new SharedSessionStorage({});
  });
});

describe('AuthClientCreateOptions', () => {
  it('takes a shared session as its storage', () => {
    new AuthClient({
      storage: new SharedSessionStorage({ url: HUB_URL }),
      syncStorage: new SyncCookieStorage({ domain: 'example.com' }),
      derivationOrigin: DERIVATION_ORIGIN,
    });
  });

  it('leaves the existing options unconstrained', () => {
    new AuthClient();
    new AuthClient({ storage: new IdbStorage() });
    new AuthClient({ syncStorage: new SyncLocalStorage() });
    // @ts-expect-error a cookie store needs the domain to scope the cookie to.
    new SyncCookieStorage({});
    new AuthClient({ derivationOrigin: DERIVATION_ORIGIN });
    new AuthClient({ keyType: 'Ed25519', transport: 'redirect', openIdProvider: 'google' });
  });
});
