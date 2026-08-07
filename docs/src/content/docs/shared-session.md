---
title: Shared Session
description: Share one sign-in across several origins of the same application.
---

An `AuthClient` keeps its session in the storage of the origin it runs on, so an application served from `https://a.example.com` and `https://b.example.com` asks the user to sign in twice, and each origin receives a different principal.

A shared session solves both halves of that. One origin holds the session and serves it to the others over `postMessage`, and a `derivationOrigin` makes every origin derive the same principal.

Nothing is written on the origins that consume the session, and the session never travels in an HTTP header — unlike a cookie, which is sent with every request to the domain and readable by any script on it.

## What authorizes an origin

The set of origins allowed to read the session is the derivation origin's [`.well-known/ii-alternative-origins`](https://github.com/dfinity/internet-identity/blob/main/docs/internet-identity-spec.adoc#alternative-frontend-origins) record — the same record Internet Identity reads when it derives a principal for an alternative origin.

Reusing it is deliberate. Every origin in that record can already obtain a delegation for the derivation origin's principal by signing in with `derivationOrigin` set, so being listed there is already full authority over the account. Serving a stored session to exactly that set grants nothing further, and it leaves one list to maintain rather than two that can drift apart.

Adding an entry to that record is therefore a security change, not configuration. Keep it to origins you deploy yourself.

## Serving the session

Deploy a page whose only job is to call `serveSharedSession`. It needs no markup and no user interaction.

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

`derivationOrigin` must match what the clients are configured with; the hub refuses a client that disagrees, because the record it holds would not be the one governing that client's identity.

Pass `canisterId` whenever the derivation origin is a different origin than the hub page. The record is then read through `https://<canisterId>.icp0.io`, where a boundary node verifies certification. Without it the record is read over the derivation origin's own domain, where anyone able to tamper with responses can widen the set of readers — a precaution Internet Identity itself takes when validating a derivation origin.

Serve the page with a `frame-ancestors` header so unrelated sites cannot even load it:

```
Content-Security-Policy: frame-ancestors 'self' https://a.example.com https://b.example.com;
```

That is defence in depth. The record above is what authorizes a reader, and it stays authoritative.

## Consuming the session

A shared session is a storage backend, so it is passed as `storage`:

```typescript
import { AuthClient } from '@icp-sdk/auth/client';
import { SharedSessionStorage } from '@icp-sdk/auth/shared-session';

const DERIVATION_ORIGIN = 'https://example.com';

const sharedSession = new SharedSessionStorage({
  hub: { url: 'https://example.com/shared-session.html' },
  derivationOrigin: DERIVATION_ORIGIN,
});

const authClient = new AuthClient({
  storage: sharedSession,
  derivationOrigin: DERIVATION_ORIGIN,
});
```

`SharedSessionStorage` requires `derivationOrigin`: without one, the same key yields a different principal on every origin, leaving a shared store holding an identity nobody else can use.

Pass the **same** derivation origin to both, as above. They are separate options, so nothing stops them differing — and if they do, this client signs in as one principal while its session is stored in a hub authorized for another. Keep it in one constant.

Signing out on any origin clears the shared store, so every origin loses the session.

## Checking for a session

`isAuthenticated()` answers synchronously, so it cannot read the shared store: that one is asynchronous and belongs to another origin. It reads the delegation's expiration from a separate synchronous store, which defaults to `localStorage` — scoped to one origin, so an origin sharing a session has nothing to read until it has restored once.

A cookie fixes that, being the only store that is both synchronous and visible across origins:

```typescript
import { SyncCookieStorage } from '@icp-sdk/auth/client';

const authClient = new AuthClient({
  storage: sharedSession,
  syncStorage: new SyncCookieStorage({
    domain: 'example.com',
    namespace: sharedSession.hubOrigin,
  }),
  derivationOrigin: DERIVATION_ORIGIN,
});
```

`domain` is what the sharing origins have in common, and must be the current host or a domain above it — a browser rejects anything else, including a sibling subdomain, and refuses a public suffix outright. Nothing needs to be served at it: a hub on `auth.example.com` can scope its cookie to `example.com` even if nothing answers there.

`namespace` keeps two shared sessions under one domain from describing each other's state, which matters for a staging deployment beside production. `hubOrigin` identifies the session, since the hub is where it lives.

The cookie holds one non-secret value, a timestamp, and its `Max-Age` comes from the delegation, so it cannot outlive the session it describes. Signing out on any origin deletes it for all of them.

It is a hint, not authority. Every subdomain can write it and nothing records which one did, so treat `isAuthenticated()` as a synchronous guess suitable for deciding what to render. The identity itself is always fetched from the shared store and verified:

```typescript
const identity = await authClient.getIdentity();
if (identity.getPrincipal().isAnonymous()) {
  await authClient.signIn();
}
```

Leave `syncStorage` unset and behaviour is unchanged from a single-origin app: correct on that origin, and correct on the others only once each has restored the session.

## Browser support

The hub is a same-site iframe, so its storage is not partitioned: Chrome, Firefox, and Safari all key third-party storage on the top-level site, and every origin here shares one registrable domain. Cross-registrable-domain sharing is not supported — that storage is partitioned, and an entry in the record pointing outside your domain simply reads an empty store.

Two consequences of relying on browser storage:

- Safari deletes script-writable storage after seven days without interaction with the site, so a returning user may need to sign in again.
- Private browsing keeps the session for the tab's lifetime only.

Both surface as "no session", which `signIn()` recovers from.

## Requirements

- The derivation origin must resolve to a canister id, which Internet Identity requires in order to read its record.
- Its record may list at most 10 origins.
- Choose the derivation origin before launch. Every principal is derived from it, so changing it later gives every user a new identity with no path back to the old one.
