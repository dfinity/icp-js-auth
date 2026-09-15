---
title: Quick Start
description: A quick start guide to using the @icp-sdk/auth package.
next:
  label: One-Click Sign-In
---

This guide offers a simple example of how to use the `@icp-sdk/auth` package to authenticate a user with [Internet Identity](https://internetcomputer.org/docs/building-apps/authentication/overview) on an Internet Computer web app.

In a web application, you can use the package in this way:

```typescript
import { AuthClient } from '@icp-sdk/auth/client';
import { HttpAgent } from '@icp-sdk/core/agent';
import { AttributesIdentity } from '@icp-sdk/core/identity';
import { Principal } from '@icp-sdk/core/principal';

const { II_AUTHORIZE_URL, II_CANISTER_ID } = process.env;

const internetIdentityCanisterId = Principal.fromText(II_CANISTER_ID);

const authClient = new AuthClient({
  identityProvider: {
    authorizeUrl: II_AUTHORIZE_URL,
    canisterId: internetIdentityCanisterId,
  },
});

// Check for an existing session (synchronous)
if (authClient.isAuthenticated()) {
  const identity = await authClient.getIdentity();
  console.log('Restored session:', identity.getPrincipal().toString());
}

// sign in and request attributes in parallel
const signInPromise = authClient.signIn();
const attributesPromise = authClient.requestAttributes({
  keys: ['email', 'name'],
  nonce: () => fetchNonceFromYourBackend(), // () => Promise<Uint8Array>
});

await signInPromise;
const { data, signature } = await attributesPromise;

// wrap the identity with attributes so canister calls include sender_info
const identity = await authClient.getIdentity();
const identityWithAttributes = new AttributesIdentity({
  inner: identity,
  attributes: { data, signature },
  signer: { canisterId: internetIdentityCanisterId },
});

const agent = await HttpAgent.create({ identity: identityWithAttributes });

// this call will include the signed attributes
await agent.call(appCanisterId, {
  methodName: 'greet',
  arg: IDL.encode([IDL.Text], ['world']),
});

// later in your app
await authClient.signOut();
```

## Next Steps

Check out the [Integrating Internet Identity](https://internetcomputer.org/docs/building-apps/authentication/integrate-internet-identity) guide for a more detailed guide on how to integrate Internet Identity into your web app.

For a full example, check out the [Who Am I](https://github.com/dfinity/examples/tree/master/motoko/who_am_i/src/internet_identity_app_frontend) example.
