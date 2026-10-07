# @icp-sdk/auth

[![NPM Version](https://img.shields.io/npm/v/%40icp-sdk%2Fauth)](https://www.npmjs.com/package/@icp-sdk/auth)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Authentication library for Internet Computer web apps.

> Still using `@dfinity/auth-client`? Migrate to [`@icp-sdk/auth`](https://js.icp.build/auth/latest/upgrading/v4)!

## Installation

```shell
npm install @icp-sdk/auth @icp-sdk/core
```

This package is only meant to be used in **browser** environments.

## Usage

```typescript
import { AuthClient } from '@icp-sdk/auth/client';

const authClient = new AuthClient();

authClient.subscribe(() => render(authClient.getStatus()));
render(authClient.getStatus());

try {
  const identity = await authClient.signIn();
  console.log('Signed in as', identity.getPrincipal().toText());
} catch (error) {
  console.error('Sign-in failed:', error);
}

// later
await authClient.signOut();
```

## Documentation

- [Guides](https://docs.internetcomputer.org/guides/authentication/internet-identity/): project setup, identity attributes, one-click sign-in, enterprise SSO, and shared sessions across subdomains.
- [API reference and upgrade guides](https://js.icp.build/auth/latest/).

## Contributing

Contributions are welcome! Please see the [contribution guide](./.github/CONTRIBUTING.md) for more information.

## License

This project is licensed under the [Apache-2.0](./LICENSE) license.
