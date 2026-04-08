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

// Check for an existing session (synchronous)
if (authClient.isAuthenticated()) {
  const identity = await authClient.getIdentity();
  console.log('Restored session:', identity.getPrincipal().toString());
}

// Log in
try {
  await authClient.login();
  const identity = await authClient.getIdentity();
  console.log('Logged in:', identity.getPrincipal().toString());
} catch (error) {
  console.error('Login failed:', error);
}

// Log out
await authClient.logout();
```

### One-Click OpenID Sign-In

Skip the Internet Identity authentication method screen and offer sign-in options like Google directly in your app:

```typescript
const authClient = new AuthClient({
  openIdProvider: 'google', // or 'apple' or 'microsoft'
});

await authClient.login();
```

### Requesting User Attributes

You can request signed user attributes at any time — during login or later when a specific feature needs them. Use `AttributesIdentity` to include the attributes in canister calls:

```typescript
import { AuthClient } from '@icp-sdk/auth/client';
import { AttributesIdentity } from '@icp-sdk/core/identity';
import { HttpAgent, Actor } from '@icp-sdk/core/agent';

const authClient = new AuthClient();

// request attributes during login
const loginPromise = authClient.login();
const attributesPromise = authClient.requestAttributes({ keys: ['email', 'name'] });

await loginPromise;
const { data, signature } = await attributesPromise;

// create an agent that includes the attributes in every call
const identity = await authClient.getIdentity();
const identityWithAttributes = new AttributesIdentity({
  inner: identity,
  attributes: { data, signature },
  signer: { canisterId: Principal.fromText('rdmx6-jaaaa-aaaaa-aaadq-cai') }, // Internet Identity canister ID
});
const agent = await HttpAgent.create({ identity: identityWithAttributes });

// the register call will include the signed email and name as attributes
const app = Actor.createActor(appIdl, { agent, canisterId });
await app.register();
```

Attributes can also be requested later, e.g. when the user accesses a feature that needs their email:

```typescript
const { data, signature } = await authClient.requestAttributes({ keys: ['email'] });

const identityWithAttributes = new AttributesIdentity({
  inner: await authClient.getIdentity(),
  attributes: { data, signature },
  signer: { canisterId: Principal.fromText('rdmx6-jaaaa-aaaaa-aaadq-cai') }, // Internet Identity canister ID
});
const agent = await HttpAgent.create({ identity: identityWithAttributes });

// the registerEmail call will include the signed email as an attribute
const app = Actor.createActor(appIdl, { agent, canisterId });
await app.registerEmail();
```

Attributes can also be scoped to a specific OpenID provider. When using one-click sign-in, scoped attributes have implicit consent — no additional user prompt is needed:

```typescript
import { AuthClient, OPENID_PROVIDER_URLS } from '@icp-sdk/auth/client';

const authClient = new AuthClient({
  openIdProvider: 'google',
});

const loginPromise = authClient.login();
const attributesPromise = authClient.requestAttributes({
  keys: [`openid:${OPENID_PROVIDER_URLS.google}:email`],
});

await loginPromise;
const { data, signature } = await attributesPromise;
```

Additional documentation can be found [here](https://js.icp.build/auth/latest/).

## Contributing

Contributions are welcome! Please see the [contribution guide](./.github/CONTRIBUTING.md) for more information.

## License

This project is licensed under the [Apache-2.0](./LICENSE) license.
