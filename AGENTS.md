# geoart

Upstream [Dekart](https://github.com/dekart-xyz/dekart) (Go backend, React frontend, AGPL-3.0) pinned
as the `lib/dekart` submodule, plus a quilt series and our own source. The artifact is a Docker image
of the patched tree. First capability: native OIDC login with server-side sessions —
[docs/oidc-login-plan.md](docs/oidc-login-plan.md).

## Two owners, disjoint

**`patches/` modifies files that exist upstream. The overlay adds files that do not.** No path may be
owned by both; `mise run overlay --check` fails if one is.

The overlay has three roots, each mirroring the upstream directory of the same name: `src/` (code),
`migrations/` (Postgres schema), `sqlite/` (SQLite schema). `src/server/user/x.go` is copied to
`lib/dekart/src/server/user/x.go`, so a Go file lands in its upstream package with no import edit.

The order is always `quilt push -a` → `mise run overlay` → build or test; `mise run up` is both halves.

## Commands

| Task | Command |
| --- | --- |
| Assemble the tree | `mise run up` |
| Back to pristine upstream | `mise run down` |
| Who owns a file | `mise run owner <path>` |
| Copy the overlay into another tree | `mise run overlay --into <root>` |
| Series integrity (10 checks) | `mise run test:series` |
| Lint every file type | `mise run lint` |
| Everything that gates a push | `mise run check` |

quilt is a system package (`pacman -S quilt`), not a mise tool. Never run `quilt` outside `mise`:
`.quiltrc` reaches quilt only through the `QUILTRC` that mise exports.

## Write facts, not prose

**A comment states what and why in one or two lines. Never more than the code it explains.** This
binds every doc and every comment in the repo.

## The quality bar

1. **Wire up Dekart's own building block** — `oidcJWTVerifier`, `validateDeviceAuthToken`,
   `validateSnapshotToken`, the device session table, `golang.org/x/oauth2`.
2. **Add a new building block, written properly**, in the overlay at the path it would have upstream.
   Architecture follows mature projects on the same stack, not Dekart's shortcuts: Grafana
   (`pkg/services/authn`, `user_auth_token`) and Coder (`coderd/httpmw/apikey.go`). Read-only clones
   live in `.upstream/` (gitignored).
3. Never a workaround.

## Write it the way Dekart does

Code in patches and overlay reads as if Vladi Bilonenko (`delfrrr`, author of every auth file) wrote it:

- One file per auth concern with a `_test.go` beside it; `claims.go` is already over 500 lines.
- A one-line purpose comment on each new function, starting with its name, and before each
  non-trivial `if`. No debug logs.
- Validators return `*Claims` or `nil` and log at `log.Warn()`. Never log a token, code or verifier —
  only presence or length, marked "(sanitized)". `log.Fatal` only for config.
- Env vars are read in `app.go` into `ClaimsCheckConfig`; booleans as `== "1"`. A new auth mode joins
  the `b2i` exclusion in `validateConfig` and `enabledSSOEnvVars()`.
- Tests: same package, testify `require`, `t.Setenv`, one table test per mode modelled on
  `TestGetContextAmazonOIDC`, `httptest` for IdP endpoints, no network.
- Proto: append enum values, `make proto`, never hand-edit generated files.

Commits here are conventional (`feat: …`, lowercase imperative, about 60 characters), enforced by hk.

## Invariants

- `patches/**` or `lib/dekart/**` → read `.claude/rules/quilt-mechanics.md` before editing.
- **A patch applying cleanly is not acceptance.** It must still be needed and still be tested.
- **An unverified claim is labelled unverified.**
