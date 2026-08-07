---
title: Shared Session
description: Share one sign-in across several origins of the same application.
---

By default a session belongs to the origin it was created on, so an application served from `docs.example.com` and `chat.example.com` asks the user to sign in twice and gives each origin a different principal.

A shared session fixes both. One origin hosts the session, the others read it from there, and a `derivationOrigin` keeps the principal the same everywhere.

You need three things: a page that hosts the session, an entry per origin in an Internet Identity record, and a few options on each client.

## 1. Host the session

Deploy a page that calls `serveSharedSession`. It needs no markup and no interaction, and can live on any origin you control — for an app on `docs.example.com` and `chat.example.com`, a dedicated `https://auth.example.com/shared-session.html` keeps it away from your application code.

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

Set `derivationOrigin` to the origin whose principal your users get — the same value every client signs in with. It must resolve to a canister, which Internet Identity requires of a derivation origin.

Serve the page with a header naming the origins allowed to embed it:

```
Content-Security-Policy: frame-ancestors 'self' https://docs.example.com https://chat.example.com;
```

## 2. Authorize each origin

Add every consuming origin to `https://auth.example.com/.well-known/ii-alternative-origins`, served with `Access-Control-Allow-Origin: *`:

```json
{ "alternativeOrigins": ["https://docs.example.com", "https://chat.example.com"] }
```

This record is the only thing that decides who may read the session, so treat adding an entry as a security change and keep it to origins you deploy yourself. Internet Identity allows at most 10.

## 3. Point each client at it

On `docs.example.com` and `chat.example.com` alike:

```typescript
import { AuthClient, SyncCookieStorage } from '@icp-sdk/auth/client';
import { SharedSessionStorage } from '@icp-sdk/auth/shared-session';

const authClient = new AuthClient({
  storage: new SharedSessionStorage({ url: 'https://auth.example.com/shared-session.html' }),
  syncStorage: new SyncCookieStorage({ domain: 'example.com' }),
  derivationOrigin: 'https://auth.example.com',
});
```

| Option | Set it to |
| --- | --- |
| `storage` | A `SharedSessionStorage` pointing at the page from step 1. |
| `derivationOrigin` | The origin that page is served from. A different value silently stores a session no other origin can use. |
| `syncStorage` | A `SyncCookieStorage` scoped to the domain you own, written without any subdomain: `example.com`. |

Set `domain` to a domain you own outright and that hosts nothing but your own applications. Never a domain shared with others, such as a hosting or gateway domain — every application under it would read and write the same cookie. Nothing needs to be served at the domain itself.

Use one shared session per domain. A second one under `example.com` would overwrite this one's state, so give a staging deployment its own domain.

Everything else is unchanged. `signIn()` and `signOut()` work as usual, and signing out on one origin ends the session on all of them.

## Checking for a session

`isAuthenticated()` is synchronous, so it answers from the cookie rather than the shared session. With `syncStorage` set it is correct on every origin from the first load; leave it unset and it returns `false` on an origin's first load until the session has been read once.

To act on the identity itself:

```typescript
const identity = await authClient.getIdentity();
if (identity.getPrincipal().isAnonymous()) {
  await authClient.signIn();
}
```

## Good to know

- Sharing works between origins on one domain. An origin on a different domain reads an empty session, even if it is listed in the record.
- Safari clears browser storage after seven days without a visit, and private windows keep it only for the tab. Both look like no session, which `signIn()` recovers from.
- Pick the derivation origin before launch. Every principal derives from it, so changing it later gives every user a new identity with no way back to the old one.
