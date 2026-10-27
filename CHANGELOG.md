# Changelog

## [1.0.0] - 2026-10-28

### Added

- SForum identity provider adapter (`sforum.connect.auth`) for Authorization Code + PKCE S256
  against a configurable SForum site (default `https://bbs.dalao.me`).
- Token exchange speaks the SForum public-unsafe contract: a JSON body plus the `csrf_` cookie
  and `X-Csrf-Token` double submit obtained from `/api/oauth/csrf`.
- Login, registration, and account-linking operations; `provider.probe` with the site's
  `/api/oauth/docs` and an authorize-endpoint fallback for older providers.
- Settings document with `base_url`, `client_id`, and `client_secret`; the base URL is prefilled
  with the official site and normalized (trailing slashes, pasted `/api/oauth`, path prefixes).
- Bounded, redirect-free HTTP client; access tokens are dropped after identity proof; every
  public error carries a stable reason and a redacted message.
- Brand assets built from the official SForum logo mark, plus CI/release pipelines and
  `scripts/prepare-package.sh`.
