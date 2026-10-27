import { Delegation, DelegationChain, Ed25519KeyIdentity } from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';
import type { Signer } from '@icp-sdk/signer';
import { describe, expect, it, vi } from 'vitest';

import { SessionGoneError } from '../../src/client/app-delegation-source.ts';
import {
  NotificationConsent,
  type NotificationConsentService,
  NotificationsUnsupportedError,
  requestNotificationConsent,
} from '../../src/client/notification-consent.ts';
import { InteractionRequiredError } from '../../src/client/session-delegation.ts';

const II = Principal.fromText('rdmx6-jaaaa-aaaaa-aaadq-cai');

const accountKey = Ed25519KeyIdentity.generate();

/** A signer whose one response is the given body, echoing the request id. */
function fakeSigner(body: Record<string, unknown>) {
  const sendRequest = vi.fn(async (request: { id: string }) => ({
    jsonrpc: '2.0',
    id: request.id,
    ...body,
  }));
  return { signer: { sendRequest } as unknown as Signer, sendRequest };
}

/** The private constructor, which is how `session-minter.test.ts` reaches its own. */
const over = (service: unknown): NotificationConsent =>
  new (NotificationConsent as unknown as new (service: unknown) => NotificationConsent)(service);

function fakeService(answers: Partial<NotificationConsentService>): NotificationConsentService {
  return {
    app_notification_consent_status: vi.fn(async () => ({ Ok: { is_granted: false } })),
    app_revoke_notification_consent: vi.fn(async () => ({ Ok: null })),
    ...answers,
  } as NotificationConsentService;
}

function chainTargeting(...perHop: (Principal[] | undefined)[]): DelegationChain {
  return DelegationChain.fromDelegations(
    perHop.map((targets) => ({
      delegation: new Delegation(
        Ed25519KeyIdentity.generate().getPublicKey().toDer(),
        1_700_000_000_000_000_000n,
        targets,
      ),
      signature: new Uint8Array([1]) as DelegationChain['delegations'][number]['signature'],
    })),
    accountKey.getPublicKey().toDer(),
  );
}

describe('requestNotificationConsent', () => {
  it('sends the provider method and reports what it granted', async () => {
    const { signer, sendRequest } = fakeSigner({ result: { granted: true } });

    await expect(requestNotificationConsent(signer)).resolves.toEqual({ granted: true });
    expect(sendRequest.mock.calls[0][0]).toMatchObject({
      jsonrpc: '2.0',
      method: 'ii_notification_consent',
    });
  });

  it('sends no derivation origin where the application has none', async () => {
    const { signer, sendRequest } = fakeSigner({ result: { granted: true } });

    await requestNotificationConsent(signer);

    expect(sendRequest.mock.calls[0][0]).toMatchObject({ params: {} });
  });

  it('passes the derivation origin the application signs in under', async () => {
    const { signer, sendRequest } = fakeSigner({ result: { granted: true } });

    await requestNotificationConsent(signer, 'https://app.example.com');

    expect(sendRequest.mock.calls[0][0]).toMatchObject({
      params: { icrc95DerivationOrigin: 'https://app.example.com' },
    });
  });

  it('reports a refusal as an answer rather than a failure', async () => {
    const { signer } = fakeSigner({ result: { granted: false } });

    await expect(requestNotificationConsent(signer)).resolves.toEqual({ granted: false });
  });

  it('names a provider that does not notify at all', async () => {
    const { signer } = fakeSigner({
      error: { code: -32601, message: 'This Internet Identity does not send notifications' },
    });

    await expect(requestNotificationConsent(signer)).rejects.toThrow(NotificationsUnsupportedError);
  });

  it('names a request that asked not to render', async () => {
    const { signer } = fakeSigner({ error: { code: 3002, message: 'Interaction required' } });

    await expect(requestNotificationConsent(signer)).rejects.toThrow(InteractionRequiredError);
  });

  it('passes any other error through as its message', async () => {
    const { signer } = fakeSigner({ error: { code: -32602, message: 'bad params' } });

    await expect(requestNotificationConsent(signer)).rejects.toThrow('bad params');
  });

  it('refuses a response that says nothing about consent', async () => {
    const { signer } = fakeSigner({ result: { granted: 'yes' } });

    await expect(requestNotificationConsent(signer)).rejects.toThrow(
      'Invalid response: missing granted',
    );
  });
});

describe('NotificationConsent.status', () => {
  it('reports what the canister recorded', async () => {
    const consent = over(
      fakeService({
        app_notification_consent_status: vi.fn(async () => ({ Ok: { is_granted: true } })),
      }),
    );

    await expect(consent.status()).resolves.toEqual({ granted: true });
  });

  it('turns NoSuchSession into the one terminal error', async () => {
    const consent = over(
      fakeService({
        app_notification_consent_status: vi.fn(async () => ({ Err: { NoSuchSession: null } })),
      }),
    );

    await expect(consent.status()).rejects.toThrow(SessionGoneError);
  });

  it("carries the canister's own explanation", async () => {
    const consent = over(
      fakeService({
        app_notification_consent_status: vi.fn(async () => ({
          Err: { InternalCanisterError: 'storage is full' },
        })),
      }),
    );

    await expect(consent.status()).rejects.toThrow(
      'Internet Identity could not report this notification consent: storage is full',
    );
  });
});

describe('NotificationConsent.revoke', () => {
  it('resolves where the canister withdrew the consent', async () => {
    const service = fakeService({});
    const consent = over(service);

    await expect(consent.revoke()).resolves.toBeUndefined();
    expect(service.app_revoke_notification_consent).toHaveBeenCalledOnce();
  });

  it('turns NoSuchSession into the one terminal error', async () => {
    const consent = over(
      fakeService({
        app_revoke_notification_consent: vi.fn(async () => ({ Err: { NoSuchSession: null } })),
      }),
    );

    await expect(consent.revoke()).rejects.toThrow(SessionGoneError);
  });

  it('raises a failed write rather than dropping it', async () => {
    const consent = over(
      fakeService({
        app_revoke_notification_consent: vi.fn(async () => ({
          Err: { InternalCanisterError: 'out of cycles' },
        })),
      }),
    );

    await expect(consent.revoke()).rejects.toThrow(
      'Internet Identity could not withdraw this notification consent: out of cycles',
    );
  });
});

describe('NotificationConsent.create', () => {
  it('refuses a chain that is not a session for the canister', async () => {
    await expect(
      NotificationConsent.create({
        sessionKey: Ed25519KeyIdentity.generate(),
        sessionChain: chainTargeting(undefined),
        canisterId: II,
      }),
    ).rejects.toThrow('names any canister');
  });
});
