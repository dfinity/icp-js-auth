---
title: One-Click Sign-In
description: Send users straight to a specific OpenID provider or to their organization's SSO, instead of the user-chosen provider.
next:
  label: Client Module
---

By default, `signIn()` opens the identity provider and the user picks how to authenticate. One-click sign-in skips that step: the user lands directly on a provider's own screen, already knowing which account they are signing in with.

There are two entry points, and a client uses at most one of them:

| Option | Use it for | Value |
| --- | --- | --- |
| `openIdProvider` | A provider the identity provider has built in | `'google'`, `'apple'`, or `'microsoft'` |
| `ssoDomain` | An organization that publishes its own OpenID configuration | The organization's domain, e.g. `'dfinity.org'` |

They select different providers for the same sign-in, so setting both is a type error and throws at construction.

## A built-in provider

```typescript
import { AuthClient } from '@icp-sdk/auth/client';

const authClient = new AuthClient({ openIdProvider: 'google' });

await authClient.signIn();
```

The user goes straight to Google's account chooser. Internet Identity is still the signer — it verifies the resulting ID token and issues the delegation — but the user never sees its sign-in screen.

## An organization's SSO

```typescript
const authClient = new AuthClient({ ssoDomain: 'dfinity.org' });

await authClient.signIn();
```

The identity provider resolves the organization's OpenID configuration from `https://dfinity.org/.well-known/ii-openid-configuration` and sends the user to the provider named there. Any organization that publishes that document can be signed in against, with nothing registered ahead of time.

The domain is normalized before it is sent: it is lowercased, IDNA-encoded, and must be a host with an optional port and nothing else. A value carrying a scheme, a path, a query, or a fragment throws.

If you pass a `derivationOrigin`, the client forwards it to the identity provider alongside the domain, so the ceremony resolves the client belonging to that origin:

```typescript
const authClient = new AuthClient({
  ssoDomain: 'dfinity.org',
  derivationOrigin: 'https://app.example.com',
});
```

## Validating a domain the user typed

An app that asks the user for their organization's domain can check it before
signing in. `isValidSsoDomain` confirms the domain is well-formed and actually
publishes an OpenID configuration:

```html
<form id="sso-form">
  <input id="sso-domain" type="text" placeholder="acme.com" autocomplete="off" required />
  <button type="submit">Continue</button>
</form>
<p id="sso-status" role="status"></p>
```

```typescript
import { AuthClient, isValidSsoDomain } from '@icp-sdk/auth/client';

const form = document.querySelector('#sso-form') as HTMLFormElement;
const input = document.querySelector('#sso-domain') as HTMLInputElement;
const status = document.querySelector('#sso-status') as HTMLParagraphElement;

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const domain = input.value.trim();

  if (!(await isValidSsoDomain(domain, AbortSignal.timeout(5_000)))) {
    status.textContent = `No SSO configuration found for ${domain}`;
    return;
  }

  const authClient = new AuthClient({ ssoDomain: domain });
  await authClient.signIn();
});
```

Two things to know about it:

- The organization must serve `/.well-known/ii-openid-configuration` with
  `Access-Control-Allow-Origin: *`. It is a public, unauthenticated document, and
  a browser that cannot read it cannot check the domain.
- The check waits on that organization's server and has no deadline of its own,
  which is why the signal is required. Aborting rejects rather than resolving
  `false`, so an abandoned check is never mistaken for an invalid domain.

To check while the user types instead, abort the previous check on each keystroke
so a superseded one cannot overwrite a fresher verdict, and debounce as well,
since every call is a request to the organization's server:

```typescript
controller?.abort();
controller = new AbortController();
const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(5_000)]);
const valid = await isValidSsoDomain(input.value, signal);
```

## Requesting attributes in the same step

When a sign-in goes to a known provider, attributes can be scoped to that same provider, and the user grants them as part of the one screen they are already on. `scopedKeys` builds those keys:

```typescript
import { AuthClient, scopedKeys } from '@icp-sdk/auth/client';

const authClient = new AuthClient({ openIdProvider: 'google' });

const signInPromise = authClient.signIn();
const attributesPromise = authClient.requestAttributes({
  keys: scopedKeys({ openIdProvider: 'google' }),
  nonce: () => fetchNonceFromYourBackend(),
});

await signInPromise;
const { data, signature } = await attributesPromise;
```

`scopedKeys({ openIdProvider: 'google' })` produces `openid:https://accounts.google.com:<key>` for `name`, `email`, and `verified_email`. The SSO form takes the domain instead:

```typescript
scopedKeys({ ssoDomain: 'dfinity.org' });
// ['sso:dfinity.org:name', 'sso:dfinity.org:email']

scopedKeys({ ssoDomain: 'dfinity.org', keys: ['email'] });
// ['sso:dfinity.org:email']
```

`verified_email` is available under `openid:` but not under `sso:`. "Verified" means Internet Identity established that the user actually has access to the address — either by verifying it itself, or through a claim scheme it has hardcoded for a specific provider, such as Google, Apple, or Microsoft. It has no basis to make that claim about an address asserted by an arbitrary organization's SSO server, so the attribute is not offered under `sso:` at all.
