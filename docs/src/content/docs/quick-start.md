---
title: Quick Start
description: Sign a user in with Internet Identity using the @icp-sdk/auth package.
---

Sign a user in with Internet Identity, use their identity, and sign out:

```typescript
import { AuthClient } from '@icp-sdk/auth/client';

const authClient = new AuthClient();

await authClient.signIn();
const identity = await authClient.getIdentity();
console.log('Signed in as', identity.getPrincipal().toText());

await authClient.signOut();
```

For everything else, see the [Internet Identity guides](https://docs.internetcomputer.org/guides/authentication/internet-identity/).
