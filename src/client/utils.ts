import type { JsonValue } from '@icp-sdk/core/candid';
import { type JsonResponse, NETWORK_ERROR, SignerError } from '@slide-computer/signer';

export const unwrapResponse = <T extends JsonValue>(response: JsonResponse<T>): T => {
  if ('error' in response) {
    throw new SignerError(response.error);
  }
  if ('result' in response) {
    return response.result;
  }
  throw new SignerError({
    code: NETWORK_ERROR,
    message: 'Invalid response',
  });
};
