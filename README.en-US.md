# SForum Connect

[![ci](https://github.com/keeptrue/sforum-connect/actions/workflows/ci.yml/badge.svg)](https://github.com/keeptrue/sforum-connect/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/keeptrue/sforum-connect)](https://github.com/keeptrue/sforum-connect/releases)

![SForum Connect social card](./plugins/sforum.connect/brand/social-preview.png)

Let any SForum site use another SForum site (the official one at `https://bbs.dalao.me` by
default) as its OAuth2 authorization server. The user clicks "Continue with SForum", signs in
there, approves the request, and comes back with an authorization code. Accounts, passwords,
callback state, PKCE, and sessions stay with the Host — this adapter does one thing: prove the
remote identity.

- Shape: SForum extension package (Manifest V3, Protocol V2 backend, `identity.runtime@1`).
  No tables, no routes, no frontend assets.
- Protocol: Authorization Code + PKCE S256. The access token is used once for userinfo and then dropped.
- Configurable: site base URL (default `https://bbs.dalao.me`, path prefixes allowed), client_id,
  client_secret.

## What it solves

A self-hosted SForum wants the account system of the official site (or of another SForum
community) without handing passwords to a third party:

```
browser ──▶ this site /auth/providers/sforum.connect.auth/start
                 │  Host mints state + PKCE verifier
                 ▼
           remote /api/oauth/authorize ── sign in + consent ──▶ callback on this site
                 │
                 ▼
            plugin: code + verifier ──▶ /api/oauth/token ──▶ /api/oauth/userinfo
                 │
                 ▼
           returns providerSubject + username/display name/email hint only
                 ▼
           Host issues a session, creates an account, or links an existing one
```

## Boundary

| The plugin does | The Host alone owns |
| --- | --- |
| Build the authorize URL from Host `state` / PKCE challenge / absolute callback | `state`, PKCE verifier, callback transaction, absolute callback URL |
| Exchange the code, read userinfo once, return the raw `providerSubject` | subject HMAC digest, users, links, roles, risk, sessions |
| Drop the access token right after identity proof | public activation, rate limits, audit, public error mapping |

No passwords, no stored tokens, no tables, no routes.

## Install

1. Download the archive for your platform from
   [Releases](https://github.com/keeptrue/sforum-connect/releases) and verify it with
   `sha256sum -c SHA256SUMS`.
2. Install it into SForum, either by uploading the zip in the admin plugin installer, or by
   unpacking it to `plugins/sforum.connect/` under a root listed in `EXTERNAL_EXTENSION_ROOTS`
   and restarting the API.
3. Enable **SForum Connect** and complete the exact-artifact `super_admin` trust confirmation.

## Prepare the remote site

1. Sign in to the remote site, open Settings → OAuth apps
   (`https://bbs.dalao.me/settings/oauth-apps`) and create an app. Administrators can also use
   the admin "OAuth2 apps" page.
2. Set the redirect URI to the callback URL shown on this site's Login methods page:

   ```
   https://your-site/auth/providers/sforum.connect.auth/callback
   ```

   For local development that is
   `http://127.0.0.1:3000/auth/providers/sforum.connect.auth/callback`; the remote site allows
   http on loopback.
3. Pick scopes. `profile` is mandatory on the remote side; add `email` if you want the
   registration form prefilled with a verified address.
4. Copy the `client_id` (`sfo_client_…`) and `client_secret` (`sfos_…`).

## Configuration

Admin → Settings → Login methods → SForum:

| Field | Notes |
| --- | --- |
| Site base URL | Defaults to `https://bbs.dalao.me`. Path prefixes are allowed (for example `https://example.com/forum`); trailing slashes and an accidentally pasted `/api/oauth` are stripped. Non-loopback hosts must use https. |
| Client ID | Public identifier of the remote app, not a secret. |
| Client Secret | Stored in SecretStore. Leave blank to keep the saved secret. |

> The remote app must be a **confidential client** (it needs a client_secret): the Host treats the plugin as
> configured only when every declared field has a stored value, so a public client without a secret cannot pass
> that gate.
>
> `base_url` has a default and is prefilled in the form; one save (together with the client
> credentials) persists it. Even before that, the plugin process falls back to the official
> site when the base URL is empty.

Saving settings restarts the plugin process — that is the Host's contract for executable
plugins, no API restart is needed.

### Why there is no scope setting

The authorize request sends **no `scope`**. The SForum authorize endpoint falls back to the
app's registered scopes when scope is omitted, so whatever the operator ticked on the remote app
is what gets granted. Sending `profile email` explicitly would make an app without the email
scope fail the whole login with `invalid_scope` — the easiest trap to fall into.

## Probe

Login methods → SForum → Run probe:

1. checks that the base URL and both credentials are present;
2. requests `<base>/api/oauth/docs` and requires the authorize, token, and userinfo endpoints;
3. for older providers without docs, falls back to calling the authorize endpoint without
   parameters — the provider answers 400 JSON, a plain SForum site answers 404;
4. states plainly that **client_secret correctness cannot be proven without an authorization
   code**. The probe never claims the secret was verified.

| reason | Meaning | Action |
| --- | --- | --- |
| `sforum.probe_ok` | Site reachable, provider ready | Enable login/registration/linking |
| `sforum.base_url_invalid` / `sforum.base_url_insecure` | Bad URL, or http on a non-loopback host | Use `https://…` |
| `sforum.client_id_missing` / `sforum.client_secret_missing` | Credentials not saved | Fill and save |
| `sforum.provider_missing` | Site reachable but no OAuth2 Provider | Enable the provider there first |
| `sforum.endpoint_unreachable` | Cannot connect | Check network, DNS, WAF |

## Enable login / registration / linking

Enabling the plugin does **not** publish a login button. Return to Login methods and turn on:

- **Login** — users with a remote account sign straight in;
- **Registration** — a remote identity without a local account goes through the external
  registration form (username and email are still entered locally; the remote email is only a
  verified hint);
- **Link** — a signed-in user binds the remote identity to the current account.

Each switch is governed by the Host activation catalog; turning one off removes its entry from
the public catalog immediately.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `invalid_grant` after the callback | Redirect URI mismatch, or the code was already used / expired (10 minutes) | The URI must match byte for byte: scheme, port, path; start over |
| `invalid_client` | Wrong client_id or client_secret | Rotate the secret on the remote app and save again |
| `invalid_scope` | The authorize request asked for a scope the app did not register | This plugin sends no scope; remove it if you changed the code |
| `invalid_token` | userinfo rejected the access token | The remote session or grant was revoked; sign in again |
| No button | Plugin not enabled / trusted / configured / operation off | Check the four state badges on the Login methods page |
| Probe 404 | Remote site has no OAuth2 Provider, or the base URL points elsewhere | Check the base URL and the remote plugin |

## Local development

```bash
# The repository root is the external extension source root.
export EXTERNAL_EXTENSION_ROOTS="$HOME/Code/github/sforum-connect"

cd plugins/sforum.connect/backend && go test ./...
scripts/prepare-package.sh          # build → digest → validate → brand check → extension test
node scripts/brand.mjs              # regenerate brand assets
```

The Host dev watcher rebuilds, re-digests, stages, and enables on every source change when
`APP_ENV=development`. Only a real component interface change needs a manual `contractVersion`
bump; this package has no components.

## Security notes

- The access token is never stored, logged, or returned; it lives inside one `CompleteIdentity`
  call stack.
- HTTP redirects are not followed: a 302 on the token endpoint would otherwise hand the
  client_secret to the redirect target.
- The token exchange follows the SForum public-unsafe contract: a JSON body plus the
  `csrf_` cookie and `X-Csrf-Token` double submit.
- Response bodies are bounded (1 MiB for token/profile, 256 KiB for probes) and every error
  message is redacted.
- The remote email is forwarded only when `emailVerified=true`.
- The remote subject is returned raw; the Host derives the HMAC digest.
- Non-loopback base URLs must be https; userinfo, query, and fragment in the base URL are rejected.

## Compatibility

- Manifest V3 + Protocol V2 (`sforum.host@2`) + `identity.runtime@1`; requires SForum `>=3.0.0`.
- The remote site needs the SForum OAuth2 Provider. Older providers without
  `/api/oauth/docs` still work; the probe uses its fallback path.

MIT License.
