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
holds only the signed-in principal and when the session ends. It is what decides
whether an origin is signed in, which is why removing it is how a sign-out
reaches the others.

Choosing a cookie domain means trusting every origin under it. Don't do this on a
domain where you don't control all the subdomains.

```typescript
import { AuthClient, CookieStateStorage } from "@icp-sdk/auth/client";

const stateStorage = new CookieStateStorage({ domain: "example.com" });
const authClient = new AuthClient({
  derivationOrigin: "https://auth.example.com",
  stateStorage,
});
```

Choosing this store also asks the identity provider to keep the sign-in, which is
what a silent re-issue in step 2 answers from. It is the store that carries that
intent, because a record reaching your siblings is the only reason to want one
kept — pass `resumable` yourself only for a cross-origin arrangement that is not
sibling subdomains, or to force it off and have each sibling sign in properly.

The derivation origin must authorize the apps. Serve this at
`https://auth.example.com/.well-known/ii-alternative-origins`:

```json
{ "alternativeOrigins": ["https://chat.example.com", "https://hr.example.com"] }
```

## 2. Acquire on page load

An app that finds the shared record naming an account it holds no credentials for
asks Internet Identity to answer from the session it already has. The user is
redirected to the provider and straight back, with no screen to interact with.

`hint` pins the re-issue to the account the record names — without it the provider
may answer for a different one, and the record would be overwritten with it.

Add a `/reauth` page that does this and returns the user to the path in `?next=`,
or home if there is nothing to answer with:

```typescript
import {
  AuthClient,
  CookieStateStorage,
  InteractionRequiredError,
} from "@icp-sdk/auth/client";

const clientOptions = {
  derivationOrigin: "https://auth.example.com",
  stateStorage: new CookieStateStorage({ domain: "example.com" }),
};

const status = new AuthClient(clientOptions).getStatus();

if (status.state === "signed-in-elsewhere") {
  const authClient = new AuthClient({
    ...clientOptions,
    transport: "redirect",
    prompt: "none",
    hint: status.principal,
  });

  try {
    await authClient.signIn({
      returnTo: new URLSearchParams(location.search).get("next") ?? "/",
    });
  } catch (error) {
    if (error instanceof InteractionRequiredError) {
      await authClient.signOut().catch(() => {});
    }
    location.replace("/");
  }
} else {
  location.replace("/");
}
```

Two clients, because `prompt` and `hint` are fixed when a client is built.

If the provider has nothing to re-issue from, the shared record is stale — sign
out to clear it, or every app on the domain keeps sending the user here.

## What ends a session on its own

A session also ends when nobody uses it. Pass `maxTimeToIdle` to `signIn()` to
say how long that may be:

```typescript
await authClient.signIn({
  // Six hours of nobody using any of these apps ends the sign-in.
  maxTimeToIdle: 6n * 60n * 60n * 1_000_000_000n,
});
```

The identity provider enforces it, so it covers every tab at once and holds
whether or not any of them is open. Omit it and the provider applies its own
default of seven days.

Using the app keeps the sign-in alive — a pointer, a key, or a request. A user who
touches nothing at all will be signed out, so don't set this near its ten-minute
minimum unless that is what you want.

Your app finds out the next time it uses the sign-in: the state becomes
`signed-out`, and the subscription from step 3 fires.

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

Ask the client to tell you when who is signed in here changes, so your views
re-run on a sign-in elsewhere, a sign-out anywhere, or a sibling offering a
session to pick up. Nothing raises an event when a cookie changes, so the record
is re-read when your page is shown or its window regains focus, which is when
the user is about to act on what they see.

```typescript
function render() {
  const auth = authClient.getStatus();
  switch (auth.state) {
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

authClient.subscribe(render);
render();
```

Four cases, and the order they exclude each other in lives in the library rather
than in your render function. `isAuthenticated()` is the same rule, narrowed to
the first one.
