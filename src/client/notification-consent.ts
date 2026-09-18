import type { Signer } from '@icp-sdk/signer';
import { InteractionRequiredError } from './session-delegation.js';

/**
 * The method Internet Identity answers a request for notification consent with.
 * Named for its provider because a JSON-RPC method travels over a transport
 * shared with other signers, unlike a canister method.
 */
const NOTIFICATION_CONSENT_METHOD = 'ii_notification_consent';

/**
 * The code Internet Identity denies a `prompt: 'none'` request with.
 *
 * In ICRC-25's 3xxx user-action range, which is what lets a caller tell a request
 * that needs a ceremony apart from a transport or protocol failure.
 */
const INTERACTION_REQUIRED_CODE = 3002;

/**
 * Asks Internet Identity whether this application may notify the user, and
 * returns what it recorded.
 *
 * A method of its own rather than a flag on sign-in, so an application can ask
 * once it knows enough about the user for the question to mean something,
 * instead of deciding before it knows anything. The cost is that it travels
 * only over the modern transport: the legacy one emits a single
 * `icrc34_delegation` request under a fixed id and rejects a response to any
 * other.
 *
 * The answer is what Internet Identity stored, not what its screen displayed, so
 * an application that was already allowed is told so without the user being
 * asked again.
 *
 * Granting also registers the user's browser to receive pushes. Nothing is sent
 * as a result of this call.
 *
 * @param signer - The signer to send the request over.
 * @param params - Request parameters.
 * @param params.derivationOrigin - The origin consent is recorded against, for
 *   an application served from more than one. Must be an origin the application
 *   is allowed to speak for, exactly as for sign-in.
 * @returns Whether this application may notify the user.
 * @throws {InteractionRequiredError} When the request asked not to render
 *   anything. Consent is the user's answer rather than a cached artifact, so
 *   there is nothing to hand back without asking.
 * @throws When the identity provider returns any other error, or a response
 *   that does not carry a boolean.
 */
export async function requestNotificationConsent(
  signer: Signer,
  params: { derivationOrigin?: string } = {},
): Promise<boolean> {
  const response = await signer.sendRequest({
    jsonrpc: '2.0',
    id: globalThis.crypto.randomUUID(),
    method: NOTIFICATION_CONSENT_METHOD,
    params:
      params.derivationOrigin === undefined
        ? {}
        : { icrc95DerivationOrigin: params.derivationOrigin },
  });

  if ('error' in response) {
    // The code carries the only thing a caller can act on: a denial for want of
    // a ceremony is answerable by asking again interactively, and every other
    // error is not.
    if (response.error.code === INTERACTION_REQUIRED_CODE) {
      throw new InteractionRequiredError(response.error.message);
    }
    throw new Error(response.error.message);
  }

  const result = response.result as { granted?: unknown } | undefined;
  if (typeof result?.granted !== 'boolean') {
    throw new Error('Invalid notification consent response: granted is missing or not a boolean');
  }

  return result.granted;
}
