---
title: Quick Start
description: A quick start guide to using the @icp-sdk/auth package.
next:
  label: Client Module
---

This guide offers a simple example of how to use the `@icp-sdk/auth` package to authenticate a user with [Internet Identity](https://internetcomputer.org/docs/building-apps/authentication/overview) on an Internet Computer web app.

In a web application, you can use the package in this way:

```typescript
import { AuthClient } from '@icp-sdk/auth/client';
import { HttpAgent } from '@icp-sdk/core/agent';

const network = 'ic'; // typically, this value is read from the environment (e.g. process.env.DFX_NETWORK)
const identityProvider =
  network === 'ic'
    ? 'https://id.ai/' // Mainnet
    : 'http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:4943'; // Local

const authClient = await AuthClient.create();
const identity = authClient.getIdentity(); // At this point, you'll get a Principal.anonymous()
console.log(await authClient.isAuthenticated()); // false

const canisterId = Principal.fromText('uqqxf-5h777-77774-qaaaa-cai');
const agent = await HttpAgent.create({
  host: 'https://icp-api.io',
});

async function onSuccess() {
  console.log('Login successful');

  const identity = authClient.getIdentity(); // At this point, you'll get an authenticated identity
  console.log(await authClient.isAuthenticated()); // true
  agent.replaceIdentity(identity);

  // this call will be authenticated
  await agent.call(canisterId, {
    methodName: 'greet',
    arg: IDL.encode([IDL.Text], ['world']),
  });
}

await authClient.login({
  identityProvider,
  onSuccess,
});

// later in your app
await authClient.logout();
```

## Rotating the Session Key

When a user initiates a new sign-in (e.g. clicks "sign in" or "switch account"), call `generateNewKey()` right before `login()`. This generates a fresh session key and clears any existing delegation, ensuring the new login uses a key that was never exposed in storage:

```typescript
// User clicks "sign in" or "switch account"
await authClient.generateNewKey();
await authClient.login({ identityProvider, onSuccess });
```

This replaces the pattern of calling `logout()` followed by a page reload, which can leave a pre-generated key in storage between sign-out and sign-in.

:::caution
Do not call `generateNewKey()` on every page load, existing sessions are preserved as normal through `AuthClient.create()` and `isAuthenticated()`.
:::

## Next Steps

Check out the [Integrating Internet Identity](https://internetcomputer.org/docs/building-apps/authentication/integrate-internet-identity) guide for a more detailed guide on how to integrate Internet Identity into your web app.

For a full example, check out the [Who Am I](https://github.com/dfinity/examples/tree/master/motoko/who_am_i/src/internet_identity_app_frontend) example.
