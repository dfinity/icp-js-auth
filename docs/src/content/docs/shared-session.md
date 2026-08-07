---
title: Shared Session
description: Share one sign-in across several origins of the same application.
---

By default a session belongs to the origin it was created on, so an application served from `a.example.com` and `b.example.com` asks the user to sign in twice and gives each origin a different principal.

A shared session fixes both. One origin hosts the session, the others read it from there, and a `derivationOrigin` keeps the principal the same everywhere.

You need three things: a page that hosts the session, an entry per origin in an Internet Identity record, and a few options on each client.

## 1. Host the session

Deploy a page that calls `serveSharedSession`. It needs no markup and no interaction — put it on any origin you control that shares a domain with your app, such as `https://example.com/shared-session.html`.

```html
<!doctype html>
<meta charset="utf-8" />
<title>Shared session</title>
<script type="module" src="/shared-session.js"></script>
```

```typescript
import { serveSharedSession } from '@icp-sdk/auth/shared-session';

serveSharedSession({
  derivationOrigin: 'https://example.com',
  canisterId: 'rdmx6-jaaaa-aaaaa-aaadq-cai',
});
```

| Option | Set it to |
| --- | --- |
| `derivationOrigin` | The origin whose principal your users get. Must resolve to a canister. Every client signs in with this same value. |
| `canisterId` | The canister behind that derivation origin. Optional when this page is served from the derivation origin itself; otherwise set it, so the allow-list is read over a verified route. |

Serve the page with a header naming the origins allowed to embed it:

```
Content-Security-Policy: frame-ancestors 'self' https://a.example.com https://b.example.com;
```

## 2. Authorize each origin

Add every consuming origin to the derivation origin's [`.well-known/ii-alternative-origins`](https://github.com/dfinity/internet-identity/blob/main/docs/internet-identity-spec.adoc#alternative-frontend-origins) record, served with `Access-Control-Allow-Origin: *`:

```json
{ "alternativeOrigins": ["https://a.example.com", "https://b.example.com"] }
```

This record is the only thing that decides who may read the session, so treat adding an entry as a security change and keep it to origins you deploy yourself. Internet Identity allows at most 10.

## 3. Point each client at it

```typescript
import { AuthClient, SyncCookieStorage } from '@icp-sdk/auth/client';
import { SharedSessionStorage } from '@icp-sdk/auth/shared-session';

const authClient = new AuthClient({
  storage: new SharedSessionStorage({ url: 'https://example.com/shared-session.html' }),
  syncStorage: new SyncCookieStorage({ domain: 'example.com' }),
  derivationOrigin: 'https://example.com',
});
```

| Option | Set it to |
| --- | --- |
| `storage` | A `SharedSessionStorage` pointing at the page from step 1. |
| `derivationOrigin` | The same value that page was given. A different one silently stores a session no other origin can use. |
| `syncStorage` | A `SyncCookieStorage` scoped to the domain your origins share, so `isAuthenticated()` is correct on first load. Optional — see below. |

`domain` must be your own domain or one above the current host, and cannot be a public suffix like `com`. Nothing needs to be served there. Assume one shared session per domain: a second one alongside it would overwrite the first's state, so give a staging deployment its own domain or leave `syncStorage` unset on it.

Everything else is unchanged. `signIn()` and `signOut()` work as usual, and signing out on one origin ends the session on all of them.

## Checking for a session

`isAuthenticated()` is synchronous, so it reads a small cookie rather than the shared session itself. Treat it as a hint for deciding what to render — any script on your domain can change it. Use the identity when it matters:

```typescript
const identity = await authClient.getIdentity();
if (identity.getPrincipal().isAnonymous()) {
  await authClient.signIn();
}
```

Without `syncStorage`, `isAuthenticated()` returns `false` on an origin's first load until the session has been read once.

## Good to know

- Sharing works between origins on one domain. A different domain reads an empty session, even if it is listed in the record.
- Safari clears browser storage after seven days without a visit, and private windows keep it only for the tab. Both look like no session, which `signIn()` recovers from.
- Pick the derivation origin before launch. Every principal derives from it, so changing it later gives every user a new identity with no way back to the old one.
