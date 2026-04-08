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
    ? 'https://id.ai/authorize' // Mainnet
    : 'http://id.ai.localhost:8000'; // default name mapping set by icp-cli when ii is enabled

const authClient = new AuthClient({ identityProvider });

// Check for an existing session (synchronous)
if (authClient.isAuthenticated()) {
  const identity = await authClient.getIdentity();
  console.log('Restored session:', identity.getPrincipal().toString());
}

const canisterId = Principal.fromText('uqqxf-5h777-77774-qaaaa-cai');
const agent = await HttpAgent.create({
  host: 'https://icp-api.io',
});

try {
  await authClient.login();
} catch (error) {
  console.error('Login failed:', error);
}

const identity = await authClient.getIdentity();
agent.replaceIdentity(identity);

// this call will be authenticated
await agent.call(canisterId, {
  methodName: 'greet',
  arg: IDL.encode([IDL.Text], ['world']),
});

// later in your app
await authClient.logout();
```

## Next Steps

Check out the [Integrating Internet Identity](https://internetcomputer.org/docs/building-apps/authentication/integrate-internet-identity) guide for a more detailed guide on how to integrate Internet Identity into your web app.

For a full example, check out the [Who Am I](https://github.com/dfinity/examples/tree/master/motoko/who_am_i/src/internet_identity_app_frontend) example.
