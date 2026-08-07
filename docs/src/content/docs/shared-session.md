---
title: Shared Session
description: Share one principal and one sign-in across several apps on your domain.
---

Use a shared session when several apps under one custom domain need the same principal and the same sign-in state, so that `docs.example.com` and `chat.example.com` sign in once as the same user.

A `derivationOrigin` alone gives them the same principal, but each app still signs in separately and keeps its own session. The setup below shares the session itself, so signing in or out of one app applies to all of them.

A shared session requires a derivation origin. The examples below use `example.com` as the custom domain and `https://auth.example.com` as the derivation origin.

## 1. Host the session

Deploy a page that calls `serveSharedSession`, on any origin you control:

```html
<!doctype html>
<meta charset="utf-8" />
<title>Shared session</title>
<script type="module" src="/shared-session.js"></script>
```

```typescript
import { serveSharedSession } from '@icp-sdk/auth/shared-session';

serveSharedSession({ derivationOrigin: 'https://auth.example.com' });
```

## 2. Authorize each app

The derivation origin decides which origins may read the session. List them in its [`.well-known/ii-alternative-origins`](https://docs.internetcomputer.org/references/internet-identity-spec/#alternative-frontend-origins) record:

```json
{ "alternativeOrigins": ["https://docs.example.com", "https://chat.example.com"] }
```

## 3. Point each app at it

On `docs.example.com` and `chat.example.com` alike:

```typescript
import { AuthClient, SharedSessionStorage, SyncCookieStorage } from '@icp-sdk/auth/client';

const authClient = new AuthClient({
  storage: new SharedSessionStorage({ url: 'https://auth.example.com/shared-session.html' }),
  syncStorage: new SyncCookieStorage({ domain: 'example.com' }),
  derivationOrigin: 'https://auth.example.com',
});
```

| Option | Set it to |
| --- | --- |
| `storage` | A `SharedSessionStorage` pointing at the page from step 1. |
| `syncStorage` | A `SyncCookieStorage` scoped to your custom domain. |
| `derivationOrigin` | The origin to derive the principal for. |
