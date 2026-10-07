---
title: Quick Start
description: Sign a user in with Internet Identity using the @icp-sdk/auth package.
---

Sign a user in with [Internet Identity](https://docs.internetcomputer.org/guides/authentication/internet-identity/), render on who is signed in, create an agent that calls canisters as that user, and sign out.

```typescript
import { AuthClient } from '@icp-sdk/auth/client';
import { HttpAgent } from '@icp-sdk/core/agent';

// Mainnet Internet Identity unless `identityProvider` says otherwise.
const authClient = new AuthClient();

// `getStatus()` is synchronous; `subscribe()` says when to read it again,
// including when another tab signs in or out.
function render() {
  const status = authClient.getStatus();
  if (status.state === 'signed-in') {
    showApp(status.principal);
  } else {
    showSignInButton();
  }
}
authClient.subscribe(render);
render();

async function signIn() {
  try {
    await authClient.signIn();
  } catch (error) {
    // The user closed the window, or the sign-in failed.
    console.error('Sign-in failed:', error);
  }
}

async function createAgent() {
  // With nobody signed in, getIdentity() returns the anonymous identity.
  if (!authClient.isAuthenticated()) return undefined;
  const identity = await authClient.getIdentity();
  return await HttpAgent.create({ identity });
}

async function signOut() {
  await authClient.signOut();
}

// When the page or component that built the client goes away.
function teardown() {
  authClient.dispose();
}
```

`getStatus()` has four states: `signed-in`, `signed-out`, `expired` (the session ended, and the status still names whose it was), and `signed-in-elsewhere` (a sibling subdomain is signed in and this origin holds no credential yet). The [Client module](/auth/latest/api/client) documents every option and method.

## Next steps

- The [Internet Identity guides](https://docs.internetcomputer.org/guides/authentication/internet-identity/) cover project setup, identity attributes, one-click sign-in, enterprise SSO, and shared sessions across subdomains.
- For a full example, see [Who Am I](https://github.com/dfinity/examples/tree/master/motoko/who_am_i).
