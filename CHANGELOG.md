# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions mirror the Dekart release they carry. Dekart's major is always 0 and
says nothing, so we drop it and keep the two components that move: Dekart
`0.27.0` ships as `27.0.0`. The last slot is ours, so `27.0.1` is the same
Dekart with a changed patch series. To read the Dekart version off ours, take
the first two fields and put `0.` in front.

Each entry also names the Dekart version in full, on its own line under the
heading.

<!-- Example:

## [99.9.0] - 9090-09-09

Dekart v0.99.9

### Changed
### Added
### Deprecated
### Removed
### Fixed
### Security

-->

## Unreleased

Dekart v0.27.0

### Fixed

- Sign out returns to Dekart: the ID token from login is kept with the session and sent as
  `id_token_hint`, which the provider requires before it honours `post_logout_redirect_uri`.

## [27.0.0] - 2026-11-18

Dekart v0.27.0

### Added

- `DEKART_REQUIRE_OIDC_LOGIN`: Dekart signs users in with any OIDC provider itself (authorization
  code with PKCE, state and nonce, endpoints from discovery), with no proxy in front.
- Server-side sessions: an opaque HttpOnly `dekart_session` cookie, the provider refresh token
  stored encrypted with `DEKART_OIDC_TOKEN_KEY`, refreshed by the server; a refused refresh ends
  the session.
- Device and snapshot tokens work in this mode, so `dekart init`, the CLI and the GeoSQL MCP
  server reach Dekart directly.
