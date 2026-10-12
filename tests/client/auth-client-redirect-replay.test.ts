import type { PublicKey } from '@icp-sdk/core/agent';
import { DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthClient } from '../../src/client/auth-client.ts';
import { LocalCredentialStorage } from '../../src/client/local-credential-storage.ts';

// Against the real `UrlTransport`, whose journal replays requests by the slot
// they were sent from: the fake used elsewhere does not model slots.

const II_CANISTER = Principal.fromText('rdmx6-jaaaa-aaaaa-aaadq-cai');

vi.mock('../../src/client/session-minter.ts', async () => {
  const { DelegationChain: Chain, Ed25519KeyIdentity: Key } = await import(
    '@icp-sdk/core/identity'
  );
  const accountKey = Key.generate();
  return {
    SessionMinter: {
      create: async () => ({
        mint: async (appPublicKey: Uint8Array) =>
          Chain.create(
            accountKey,
            { toDer: () => appPublicKey } as unknown as PublicKey,
            new Date(Date.now() + 5 * 60 * 1000),
          ),
        revoke: async () => {},
      }),
    },
  };
});

const ORIGIN = 'https://relying.example.com';
const PATH = '/connect';

const toBase64 = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes));
const fromBase64 = (value: string): Uint8Array =>
  Uint8Array.from(atob(value), (char) => char.charCodeAt(0));

const flush = async () => {
  for (let i = 0; i < 15; i++) await new Promise((r) => setTimeout(r, 0));
};

function stubLoad(hash: string) {
  const location = {
    origin: ORIGIN,
    pathname: PATH,
    search: '',
    hash,
    href: `${ORIGIN}${PATH}${hash}`,
    assign: vi.fn<(url: string) => void>(),
    replace: vi.fn<(url: string) => void>(),
  };
  vi.stubGlobal('location', location);
  vi.stubGlobal('history', {
    state: null,
    replaceState: (_state: unknown, _title: string, url: string) => {
      location.hash = new URL(url, ORIGIN).hash;
    },
  });
  return location;
}

type Request = { id: string; method: string; params: Record<string, unknown> };

async function answer(request: Request) {
  if (request.method === 'ii-icrc3-attributes') {
    return {
      jsonrpc: '2.0',
      id: request.id,
      result: { data: btoa('attributes'), signature: btoa('signature') },
    };
  }
  const sessionKey = fromBase64(request.params.sessionPublicKey as string);
  const chain = await DelegationChain.create(
    Ed25519KeyIdentity.generate(),
    { toDer: () => sessionKey } as unknown as PublicKey,
    new Date(Date.now() + 3.6e6),
    { targets: [II_CANISTER] },
  );
  return {
    jsonrpc: '2.0',
    id: request.id,
    result: {
      publicKey: toBase64(new Uint8Array(chain.publicKey)),
      signerDelegation: chain.delegations.map((sd) => ({
        delegation: {
          pubkey: toBase64(new Uint8Array(sd.delegation.pubkey)),
          expiration: sd.delegation.expiration.toString(),
          targets: sd.delegation.targets?.map((t) => t.toText()),
        },
        signature: toBase64(new Uint8Array(sd.signature)),
      })),
    },
  };
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('AuthClient redirect replay (real UrlTransport)', () => {
  it.each([
    ['signIn first', true],
    ['requestAttributes first', false],
  ])(
    'completes signIn and requestAttributes issued together, %s, when the nonce is slow only on the first load',
    async (_, signInFirst) => {
      const credentialStorage = new LocalCredentialStorage();
      const keys = ['name', 'verified_email'];
      const run = (client: AuthClient, nonce: () => Promise<Uint8Array>) => {
        if (signInFirst) {
          const identity = client.signIn();
          return Promise.all([identity, client.requestAttributes({ keys, nonce })]);
        }
        const attributes = client.requestAttributes({ keys, nonce });
        return Promise.all([client.signIn(), attributes]);
      };

      // First load: the nonce arrives after the delegation request is ready.
      const first = stubLoad('');
      const client1 = new AuthClient({ transport: 'redirect', credentialStorage });
      let releaseNonce!: () => void;
      const nonce = new Promise<Uint8Array>((resolve) => {
        releaseNonce = () => resolve(new Uint8Array(32).fill(7));
      });
      void run(client1, () => nonce).catch(() => undefined);
      await flush();
      releaseNonce();
      await flush();
      expect(first.assign).toHaveBeenCalledOnce();

      const fragment = new URLSearchParams(first.assign.mock.calls[0][0].split('#')[1]);
      const sent = JSON.parse(fragment.get('message') as string) as Request | Request[];
      const responses = await Promise.all((Array.isArray(sent) ? sent : [sent]).map(answer));
      client1.dispose();

      // Return load: the nonce replays from the journal at once.
      stubLoad(
        `#${new URLSearchParams({ message: JSON.stringify(responses), state: fragment.get('state') as string })}`,
      );
      const client2 = new AuthClient({ transport: 'redirect', credentialStorage });
      const fetchAgain = vi.fn<() => Promise<Uint8Array>>();
      const [identity, attributes] = await run(client2, fetchAgain);

      expect(fetchAgain).not.toHaveBeenCalled();
      expect(identity.getPrincipal().isAnonymous()).toBe(false);
      expect(new TextDecoder().decode(attributes.data)).toBe('attributes');
      client2.dispose();
    },
  );
});
