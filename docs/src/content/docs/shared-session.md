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

```typescript
import { AuthClient } from '@icp-sdk/auth/client';

const authClient = new AuthClient({
  sharedSessionHub: { url: 'https://example.com/shared-session.html' },
  derivationOrigin: 'https://example.com',
});
```

`sharedSessionHub` requires `derivationOrigin` and replaces `storage`. Without a shared derivation origin the same key would yield a different principal on every origin, leaving a shared store holding an identity nobody else can use — so the type system requires the two together.

Signing out on any origin clears the shared store, so every origin loses the session.

## Checking for a session

`isAuthenticated()` answers synchronously, so it cannot read the shared store: that one is asynchronous and belongs to another origin. It reads the delegation's expiration from a separate synchronous store instead — `localStorage` normally, and a cookie scoped to the derivation origin's domain when `sharedSessionHub` is set.

The cookie is what makes the answer correct across origins. It holds one non-secret value, a timestamp, and its `Max-Age` matches the delegation, so it cannot outlive the session it describes. Signing out on any origin deletes it for all of them.

It is a hint, not authority. Every subdomain can write it and nothing records which one did, so treat `isAuthenticated()` as a synchronous guess suitable for deciding what to render. The identity itself is always fetched from the shared store and verified:

```typescript
const identity = await authClient.getIdentity();
if (identity.getPrincipal().isAnonymous()) {
  await authClient.signIn();
}
```

A cookie can only be scoped to the current host or a domain above it, so this needs the derivation origin to be a **parent** of the consuming origins — `https://example.com` for clients on `a.example.com` and `b.example.com`. With a sibling derivation origin (`auth.example.com` alongside `a.example.com`) the cookie is unreachable, so `localStorage` is used instead and `isAuthenticated()` is correct only after that origin has restored the session once.

Supply `syncStorage` to override the choice entirely.

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
