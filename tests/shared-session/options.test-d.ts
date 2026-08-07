import { describe, it } from 'vitest';
import { AuthClient } from '../../src/client/auth-client.ts';
import { IdbStorage } from '../../src/client/storage.ts';

const HUB = { url: 'https://auth.example.com/hub.html' };
const DERIVATION_ORIGIN = 'https://auth.example.com';

describe('AuthClientCreateOptions', () => {
  it('accepts a hub together with a derivation origin', () => {
    new AuthClient({ sharedSessionHub: HUB, derivationOrigin: DERIVATION_ORIGIN });
    new AuthClient({
      sharedSessionHub: { ...HUB, timeout: 5_000 },
      derivationOrigin: new URL(DERIVATION_ORIGIN),
    });
  });

  it('requires a derivation origin alongside a hub', () => {
    // @ts-expect-error a shared session without a shared derivation origin would
    // give each origin a different principal from the same key.
    new AuthClient({ sharedSessionHub: HUB });
  });

  it('refuses a custom storage alongside a hub', () => {
    new AuthClient({
      sharedSessionHub: HUB,
      derivationOrigin: DERIVATION_ORIGIN,
      // @ts-expect-error the hub supplies the store.
      storage: new IdbStorage(),
    });
  });

  it('leaves the existing options unconstrained', () => {
    new AuthClient();
    new AuthClient({ storage: new IdbStorage() });
    new AuthClient({ derivationOrigin: DERIVATION_ORIGIN });
    new AuthClient({ storage: new IdbStorage(), derivationOrigin: DERIVATION_ORIGIN });
    new AuthClient({ keyType: 'Ed25519', transport: 'redirect', openIdProvider: 'google' });
  });
});
