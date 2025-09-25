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

const identityProvider = 'https://id.ai/';

const authClient = await AuthClient.create();
const identity = authClient.getIdentity(); // At this point, you'll get a Principal.anonymous()

async function onSuccess() {
  console.log('Login successful');

  const identity = authClient.getIdentity(); // At this point, you'll get an authenticated identity
  console.log(authClient.isAuthenticated()); // true
}

await authClient.login({
  identityProvider,
  onSuccess,
});

// later in your app
await authClient.logout();
```

Additional documentation can be found [here](https://js.icp.build/auth/latest/).

## Contributing

Contributions are welcome! Please see the [contribution guide](./.github/CONTRIBUTING.md) for more information.

## License

This project is licensed under the [Apache-2.0](./LICENSE) license.
