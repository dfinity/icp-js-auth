# @icp-sdk/auth

[![NPM Version](https://img.shields.io/npm/v/%40icp-sdk%2Fauth)](https://www.npmjs.com/package/@icp-sdk/auth)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Authentication library for Internet Computer web apps.

> Still using `@dfinity/auth-client`? Migrate to [`@icp-sdk/auth`](https://js.icp.build/auth/latest/upgrading/v4)!

---

## Installation

You can install the `@icp-sdk/auth` package with your package manager of choice:

### npm

```shell
npm install @icp-sdk/auth
```

### pnpm

```shell
pnpm add @icp-sdk/auth
```

### yarn

```shell
yarn add @icp-sdk/auth
```

> Note: this package is only meant to be used in **browser** environments.

## Usage Example

Here's a simple example of how to use the `@icp-sdk/auth` package to authenticate a user with Internet Identity on an Internet Computer web app:

```typescript
import { AuthClient } from '@icp-sdk/auth/client';

const authClient = new AuthClient();

// restore an existing session if there is one, otherwise sign in
let identity;
try {
  identity = authClient.isAuthenticated()
    ? await authClient.getIdentity()
    : await authClient.signIn();
} catch (error) {
  console.error('Sign-in failed:', error);
  throw error;
}

console.log('Identity:', identity.getPrincipal().toString());

// later, to end the session
await authClient.logout();
```

### One-Click OpenID Sign-In

Skip the Internet Identity authentication method screen and offer sign-in options like Google directly in your app:

```typescript
const authClient = new AuthClient({
  openIdProvider: 'google', // or 'apple' or 'microsoft'
});
```

### Requesting Identity Attributes

Internet Identity can provide signed identity attributes (e.g., email) alongside authentication. Your backend canister initiates the flow by issuing a nonce tied to the action — this way, even if an attribute bundle is intercepted, it can't be replayed or used for a different action.

Here's a registration flow where the backend needs the user's email:

```typescript
import { AuthClient } from '@icp-sdk/auth/client';
import { AttributesIdentity } from '@icp-sdk/core/identity';
import { HttpAgent, Actor } from '@icp-sdk/core/agent';

const authClient = new AuthClient();

// the backend issues a nonce scoped to registration —
// this starts the action and binds the upcoming attributes to it
const anonymousAgent = await HttpAgent.create();
const backend = Actor.createActor(backendIdl, { agent: anonymousAgent, canisterId });
const nonce: Uint8Array = await backend.registerBegin();

// sign-in and attribute request happen in parallel — the user sees a single II interaction
try {
  const signInPromise = authClient.signIn();
  const attributesPromise = authClient.requestAttributes({ keys: ['email'], nonce });

  const identity = await signInPromise;
  const { data, signature } = await attributesPromise;

  // wrap the identity so the signed attributes are included in the canister call
  const identityWithAttributes = new AttributesIdentity({
    inner: identity,
    attributes: { data, signature },
    signer: { canisterId: Principal.fromText('rdmx6-jaaaa-aaaaa-aaadq-cai') }, // Internet Identity canister ID
  });
  const agent = await HttpAgent.create({ identity: identityWithAttributes });
  const app = Actor.createActor(appIdl, { agent, canisterId });

  // the backend verifies the nonce, origin, and timestamp, then extracts the email
  await app.registerFinish();
} catch (error) {
  console.error('Registration failed:', error);
}
```

The signed attribute bundle includes implicit fields that your backend canister should verify:

- **`implicit:nonce`** — ties the attributes to a specific canister-initiated action, preventing replay and cross-action reuse. Must originate from the backend, not the frontend.
- **`implicit:origin`** — the requesting origin, verified by the canister to prevent a malicious dapp from forwarding attribute bundles to your backend.
- **`implicit:issued_at_timestamp_ns`** — issuance timestamp, allowing the canister to reject stale attributes even if the nonce hasn't expired yet.

> Attributes can also be requested after sign-in — for example, when a user later triggers an action like linking an email. The flow is the same: the backend issues a nonce for that action, the frontend calls `requestAttributes`, and the backend verifies the result.

#### OpenID-Scoped Attributes

When using one-click sign-in, attributes can be scoped to the OpenID provider. Scoped attributes have implicit consent — the user authenticates and shares attributes in a single step without an additional prompt:

```typescript
import { AuthClient, scopedKeys } from '@icp-sdk/auth/client';

const authClient = new AuthClient({
  openIdProvider: 'google',
});

const nonce: Uint8Array = await backend.registerBegin();
const signInPromise = authClient.signIn();
// requests name, email, and verified_email from the
// Google account linked to the user's Internet Identity
const attributesPromise = authClient.requestAttributes({
  keys: scopedKeys({ openIdProvider: 'google' }),
  nonce,
});

await signInPromise;
const { data, signature } = await attributesPromise;
// ... wrap with AttributesIdentity and complete the action as above
```

Additional documentation can be found [here](https://js.icp.build/auth/latest/).

## Contributing

Contributions are welcome! Please see the [contribution guide](./.github/CONTRIBUTING.md) for more information.

## License

This project is licensed under the [Apache-2.0](./LICENSE) license.
