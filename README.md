# discourse-resonite-oauth

Discourse plugin that signs users in with a **Resonite** account using OAuth 2.0 / OpenID Connect against [account.resonite.com](https://account.resonite.com/).

## Redirect URL

When you register your OAuth client with Resonite, set the redirect (callback) URL to:

`https://<your-forum-hostname>/auth/resonite/callback`

Example: `https://community.example.com/auth/resonite/callback`.

See the [Resonite wiki OAuth page](https://wiki.resonite.com/OAuth) for application registration and scopes.

## Site settings

Enable **resonite oauth enabled**, then set **client id** and **client secret** from your registered Resonite application.

Discovery defaults to `https://account.resonite.com/.well-known/openid-configuration`. You can override it with **resonite oauth discovery document url** if needed.

Scopes default to `openid profile email offline_access` so Discourse can load [profile data](https://wiki.resonite.com/OAuth#Profile_Endpoint) (including email and avatar). Avatars use `resdb:///` links converted to `https://assets.resonite.com/<hash>` per the [Resonite API](https://wiki.resonite.com/API).

## Upgrading from generic OIDC (`oidc`)

This plugin previously used provider name `oidc` and paths such as `/auth/oidc/callback`. It now uses **`resonite`** and **`/auth/resonite/callback`**.

Existing `user_associated_accounts` rows with `provider_name = 'oidc'` will not match the new provider. Users must sign in again to link Resonite, or you can run a one-off SQL migration if you control the database and accept the risk (not provided here).

## Development

This repository is a plugin directory. Run it inside a [Discourse](https://github.com/discourse/discourse) development or test environment with the plugin symlinked or cloned under `plugins/`.
