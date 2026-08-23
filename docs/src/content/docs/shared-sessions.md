---
title: Shared sessions across subdomains
description: Sign in once and be signed in across sibling subdomains of one domain.
---

## Overview

Apps on sibling subdomains of one domain, such as `chat.example.com` and
`hr.example.com`, can share one sign-in. Sign in on one and the others are signed
in too, without a second visit to the identity provider; sign out of one and the
others follow within five minutes.

Setup is three steps: share the session, sign in on page load, and reflect the
session in your UI.

## 1. Share the session

Every app builds its `AuthClient` with the same `derivationOrigin` and the same
cookie `domain`, so a sign-in on one writes a cookie the others read. The cookie
holds only the signed-in principal and the session's expiry.

```typescript
import { AuthClient, CookieSessionStorage } from "@icp-sdk/auth/client";

const cookieStorage = new CookieSessionStorage({ domain: "example.com" });
const authClient = new AuthClient({
  derivationOrigin: "https://auth.example.com",
  sessionStorage: cookieStorage,
});
```

The derivation origin must authorize the apps. Serve this at
`https://auth.example.com/.well-known/ii-alternative-origins`:

```json
{ "alternativeOrigins": ["https://chat.example.com", "https://hr.example.com"] }
```

## 2. Sign in on page load

Add a `/reauth` page that re-issues this app's own delegation from the shared
session and returns the user to the path in `?next=`, or home if there is
nothing to re-issue. Serve it at `/reauth`:

```typescript
import { AuthClient, CookieSessionStorage } from "@icp-sdk/auth/client";

const cookieStorage = new CookieSessionStorage({ domain: "example.com" });
const authClient = new AuthClient({
  derivationOrigin: "https://auth.example.com",
  transport: "redirect",
  sessionStorage: cookieStorage,
  prompt: "none",
  hint: cookieStorage.readHint()?.principal,
});

await authClient
  .signIn({ returnTo: new URLSearchParams(location.search).get("next") ?? "/" })
  .catch(() => location.replace("/"));
```

`/reauth` is a redirect callback, so list it at
`https://chat.example.com/.well-known/ii-auth-callbacks`:

```json
{ "callbacks": ["https://chat.example.com/reauth"] }
```

On every other page, redirect to `/reauth` on load when a sibling is signed in
but this app has no session yet:

```typescript
if (!authClient.isAuthenticated() && cookieStorage.readHint()) {
  location.replace(
    `/reauth?next=${encodeURIComponent(location.pathname + location.search)}`,
  );
}
```

## What signing out does

`signOut()` ends the session at the identity provider, then clears this app's own
state and removes the shared cookie.

Because the siblings share one session, ending it ends what any of them can
obtain. Each holds a delegation of its own that stays valid until it expires, so
a sibling mid-request finishes it, and the next delegation it asks for is refused.
That window is five minutes rather than the session's full length, which is what
makes a sign-out reach the other apps at all.

Every sibling also stops offering the session as soon as the cookie is gone, so
their next render shows signed out.

## 3. Reflect the session in your UI

Reflect the session in your own views, and subscribe so the UI re-runs whenever
the session changes in another tab or app: a sign-in elsewhere, a sign-out
anywhere, or a sibling offering a session to resume.

```typescript
function render() {
  if (authClient.isAuthenticated()) {
    showSignedIn();
  } else if (cookieStorage.readHint()) {
    // A sibling app has a session; offer to pick it up, for example with a
    // "You're signed in on another app" banner whose button runs the re-auth.
    showResumePrompt(() =>
      location.replace(
        `/reauth?next=${encodeURIComponent(location.pathname + location.search)}`,
      ),
    );
  } else {
    showSignedOut();
  }
}

authClient.subscribe(render);
```
