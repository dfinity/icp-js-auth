---
title: Shared sessions across subdomains
description: Sign in once and be signed in across sibling subdomains of one domain.
---

## Overview

Apps on sibling subdomains of one domain, such as `chat.example.com` and
`hr.example.com`, can share one sign-in. Sign in on one and the others are signed
in too, without a second visit to the identity provider; sign out of one and the
others follow within five minutes.

Setup is three steps: share the state, acquire on page load, and reflect it in
your UI.

## 1. Share the state

Every app builds its `AuthClient` with the same `derivationOrigin` and the same
cookie `domain`, so a sign-in on one writes a record the others read. The record
holds only the signed-in principal and when the session ends — no chain and no
key, so it is not something a sibling can act with. It is what decides whether an
origin is signed in, which is why removing it is how a sign-out reaches the
others.

```typescript
import { AuthClient, CookieStateStorage } from "@icp-sdk/auth/client";

const stateStorage = new CookieStateStorage({ domain: "example.com" });
const authClient = new AuthClient({
  derivationOrigin: "https://auth.example.com",
  stateStorage,
});
```

The derivation origin must authorize the apps. Serve this at
`https://auth.example.com/.well-known/ii-alternative-origins`:

```json
{ "alternativeOrigins": ["https://chat.example.com", "https://hr.example.com"] }
```

## 2. Acquire on page load

An app that finds the shared record naming an account it holds no credentials for
asks Internet Identity to answer from the session it already has. Nothing is
rendered: `prompt: "none"` says the request may be answered without the user, and
`hint` names which account to answer for.

Add a `/reauth` page that does this and returns the user to the path in `?next=`,
or home if there is nothing to answer with:

```typescript
import { AuthClient, CookieStateStorage } from "@icp-sdk/auth/client";

const stateStorage = new CookieStateStorage({ domain: "example.com" });
const authClient = new AuthClient({
  derivationOrigin: "https://auth.example.com",
  transport: "redirect",
  stateStorage,
  prompt: "none",
  hint: stateStorage.get()?.principal,
});

await authClient
  .signIn({ returnTo: new URLSearchParams(location.search).get("next") ?? "/" })
  .catch((error) => {
    // The identity provider says there is nothing to re-issue from: the session
    // was revoked or expired rather than replaced. That is the only reliable
    // evidence the shared record is stale, so this is the one place an origin
    // may retract what it did not write.
    if (isInteractionRequired(error)) stateStorage.remove();
    location.replace("/");
  });
```

This reads the record directly rather than going through `getStatus()`, because
`hint` is a constructor option: the account has to be named before there is a
client to ask. Everywhere else, `getStatus()` is what you want.

`prompt` and `hint` are fixed when the client is built, so this is a separate
client from the one your app signs in with interactively. Both share the same
storage, so whichever resolves populates the same session.

`/reauth` is a redirect callback, so list it at
`https://chat.example.com/.well-known/ii-auth-callbacks`:

```json
{ "callbacks": ["https://chat.example.com/reauth"] }
```

On every other page, redirect to `/reauth` on load when the shared record names
someone but this app has nothing to act with yet:

```typescript
if (authClient.getStatus().status === "signed-in-elsewhere") {
  location.replace(
    `/reauth?next=${encodeURIComponent(location.pathname + location.search)}`,
  );
}
```

`getStatus()` is what separates the two questions. `isAuthenticated()` answers
*can this origin act*; the shared record answers *is anyone signed in on this
domain*, which every sibling reads the same. A sibling that has not acquired a
credential of its own is `signed-in-elsewhere`, and that is the case this
redirect exists for.

If your app asks for an identity before the redirect runs, it will not be handed
an anonymous one — `getIdentity()` rejects with `SessionNotHeldError` rather than
letting unauthenticated calls go out while the record says someone is signed in.

## What signing out does

`signOut()` ends the session at the identity provider, then clears this app's own
credentials and removes the shared record.

Because the siblings share one session, ending it ends what any of them can
obtain. Each holds a delegation of its own that stays valid until it expires, so
a sibling mid-request finishes it and the next one it asks for is refused. That
window is five minutes rather than the session's full length, which is what makes
a sign-out reach the other apps at all.

Every sibling also stops reading the record as soon as it is gone, so their next
render shows signed out.

A sign-in elsewhere is not a sign-out. Signing in again replaces the browser's
session, so a sibling still holding a chain to the old one finds out on its next
mint — and drops what it holds while leaving the shared record alone, because
that record belongs to the sign-in that replaced it. Its own reads then report
`held: false`, which sends it through `/reauth`, and the user sees nothing.

A revoked session looks identical at that moment, so the difference only shows in
what `/reauth` gets back: a replacement resolves silently, while a session that is
genuinely gone comes back `interaction_required` — and that is what tells the
origin the shared record is stale and may be removed.

## 3. Reflect it in your UI

Subscribe to the state so your views re-run whenever it changes — a sign-in
elsewhere, a sign-out anywhere, or a sibling offering a session to pick up.
Nothing raises an event when a cookie changes, so the record is re-read when your
page is shown or its window regains focus, which is when the user is about to act
on what they see.

```typescript
function render() {
  const auth = authClient.getStatus();
  switch (auth.status) {
    case "signed-in":
      return showSignedIn(auth.principal);
    case "expired":
      // The record outlives the session on purpose, so this is a "your session
      // ended, sign back in" screen rather than a bare signed-out one.
      return showSessionExpired(auth.principal);
    case "signed-in-elsewhere":
      // Someone is signed in on this domain and this origin holds nothing for
      // them, for example a "You're signed in on another app" banner whose
      // button runs the re-auth.
      return showResumePrompt(() =>
        location.replace(
          `/reauth?next=${encodeURIComponent(location.pathname + location.search)}`,
        ),
      );
    case "signed-out":
      return showSignedOut();
  }
}

stateStorage.subscribe(render);
render();
```

Four cases, and the order they exclude each other in lives in the library rather
than in your render function. `isAuthenticated()` is the same rule, narrowed to
the first one.
