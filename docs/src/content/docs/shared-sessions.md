---
title: Shared sessions across subdomains
description: Sign in once and be signed in across sibling subdomains of one domain.
---

Several apps on sibling subdomains of one domain (`chat.example.com`,
`hr.example.com`) can share a single sign-in: sign in on one and the others are
signed in too, sign out of one and the others follow.

Two pieces make this work, and both are options on `AuthClient`:

- A `derivationOrigin` gives every app the same principal. On its own it does
  not share the session, so each app would still sign in separately.
- A `SyncCookieStorage` shares the sign-in *state* across the subdomains, and a
  silent `prompt: 'none'` sign-in acquires the session on an app that does not
  have it yet.

The cookie holds only the signed-in principal and the delegation's expiry. It
never holds the delegation or any key material, and it is scoped to your domain,
so it is not visible to unrelated sites.

## Configure each app

Every app uses the same `derivationOrigin` and the same cookie `domain`. Use the
`'redirect'` transport, so a silent sign-in on page load needs no popup.

```typescript
import { AuthClient, SyncCookieStorage } from '@icp-sdk/auth/client';

const IDENTITY_PROVIDER = 'https://id.ai/authorize';
const DERIVATION_ORIGIN = 'https://auth.example.com';
const DOMAIN = 'example.com';

// One instance, shared by the clients below, so they read one cookie.
const syncStorage = new SyncCookieStorage({ domain: DOMAIN });

const shared = {
  identityProvider: IDENTITY_PROVIDER,
  derivationOrigin: DERIVATION_ORIGIN,
  transport: 'redirect',
  syncStorage,
} as const;
```

The `'redirect'` transport returns to the current page, so that page's origin
must list its own URL in its `/.well-known/ii-auth-callbacks` file:

```json
{ "callbacks": ["https://chat.example.com/"] }
```

## Sign in and sign out

An interactive sign-in uses `prompt: 'login'`, which runs the ceremony and lets
Internet Identity keep the delegation so the other apps can re-acquire it
silently later.

```typescript
document.querySelector('#signin').onclick = () => {
  new AuthClient({ ...shared, prompt: 'login' }).signIn();
};

document.querySelector('#signout').onclick = async () => {
  // Clears this app's session and the shared cookie, so the siblings sign out too.
  await new AuthClient({ ...shared }).signOut();
};
```

## Acquire the session on page load

On load, an app that has no local session but sees the shared cookie acquires
its own delegation silently, with `prompt: 'none'` and the announced principal
as `hint`. Run this at the top of the page, not behind a click, so the redirect
can complete on the return visit.

```typescript
import { KEY_STORAGE_DELEGATION } from '@icp-sdk/auth/client';

const probe = new AuthClient({ ...shared });
if (!probe.isAuthenticated()) {
  const session = syncStorage.readHint(KEY_STORAGE_DELEGATION);
  if (session) {
    // A sibling is signed in. Acquire our own delegation without a ceremony;
    // this redirects and returns, completing on the next load.
    await new AuthClient({ ...shared, prompt: 'none', hint: session.principal }).signIn();
  }
}
```

If Internet Identity has nothing to re-issue, the `prompt: 'none'` sign-in
rejects with an `interaction_required` error rather than showing anything;
treat that as "not signed in" and leave the app anonymous.

## React to sign-in and sign-out in other tabs and apps

`AuthClient.subscribe` fires when the session changes elsewhere, so an open page
can update without a reload. A sign-out on any subdomain, or a sign-in in another
tab of the same origin, reaches every subscribed client.

```typescript
const authClient = new AuthClient({ ...shared });
const unsubscribe = authClient.subscribe(() => {
  render(authClient.isAuthenticated());
});
```

A same-origin sign-in in another tab is adopted automatically. A sign-in on a
different subdomain cannot be adopted silently from an event (it needs the
`prompt: 'none'` redirect above), so there the callback signals that a session
is available to acquire while `isAuthenticated()` is still `false`.
