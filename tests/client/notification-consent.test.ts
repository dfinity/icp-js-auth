import type { Signer } from '@icp-sdk/signer';
import { describe, expect, it } from 'vitest';

import { requestNotificationConsent } from '../../src/client/notification-consent.ts';
import { InteractionRequiredError } from '../../src/client/session-delegation.ts';

const signerAnswering = (response: unknown) => {
  const requests: Record<string, unknown>[] = [];
  const signer = {
    sendRequest: async (request: unknown) => {
      requests.push(request as Record<string, unknown>);
      return response;
    },
  } as unknown as Signer;
  return { signer, requests };
};

const granted = (value: boolean) => ({ jsonrpc: '2.0', id: '1', result: { granted: value } });
const failed = (code: number, message: string) => ({
  jsonrpc: '2.0',
  id: '1',
  error: { code, message },
});

describe('requestNotificationConsent', () => {
  it('asks over the method Internet Identity answers, under an id of its own', async () => {
    const { signer, requests } = signerAnswering(granted(true));

    await requestNotificationConsent(signer);

    expect(requests[0]?.method).toBe('ii_notification_consent');
    expect(typeof requests[0]?.id).toBe('string');
    expect(requests[0]?.params).toEqual({});
  });

  it('names the derivation origin when the application is served from more than one', async () => {
    const { signer, requests } = signerAnswering(granted(true));

    await requestNotificationConsent(signer, { derivationOrigin: 'https://app.example.com' });

    expect(requests[0]?.params).toEqual({ icrc95DerivationOrigin: 'https://app.example.com' });
  });

  it('reports what was recorded, including a refusal', async () => {
    const allowed = signerAnswering(granted(true));
    const refused = signerAnswering(granted(false));

    await expect(requestNotificationConsent(allowed.signer)).resolves.toBe(true);
    await expect(requestNotificationConsent(refused.signer)).resolves.toBe(false);
  });

  it('tells a silent request apart from a failure, so the caller can ask for real', async () => {
    const { signer } = signerAnswering(failed(3002, 'Interaction required'));

    await expect(requestNotificationConsent(signer)).rejects.toBeInstanceOf(
      InteractionRequiredError,
    );
  });

  it('raises any other error as itself rather than as a denial', async () => {
    const { signer } = signerAnswering(failed(-32602, 'Invalid params'));

    await expect(requestNotificationConsent(signer)).rejects.toThrow('Invalid params');
    await expect(requestNotificationConsent(signer)).rejects.not.toBeInstanceOf(
      InteractionRequiredError,
    );
  });

  it('refuses a response that carries no answer', async () => {
    for (const result of [{}, { granted: 'yes' }, { granted: null }, undefined]) {
      const { signer } = signerAnswering({ jsonrpc: '2.0', id: '1', result });
      await expect(requestNotificationConsent(signer)).rejects.toThrow(
        'granted is missing or not a boolean',
      );
    }
  });
});
