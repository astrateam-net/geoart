#!/usr/bin/env bash
#MISE description="Tests the series and the overlay carry: their Go packages and vitest files"
#MISE dir="{{config_root}}"
#MISE depends=["up"]
# Scoped like orca-server's test:unit: upstream's whole suite needs cloud credentials.
set -Eeuo pipefail

# Inherited git env would point `git -C` at the outer repo — see .mise/lib.sh.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY

# Every path the overlay or a patch owns, relative to lib/dekart.
touched() {
  {
    local r
    for r in src migrations sqlite; do
      [ -d "$r" ] && find "$r" -type f
    done
    grep -hs '^+++ [^/]*/lib/dekart/' patches/*.diff | sed 's|^+++ [^/]*/lib/dekart/||; s/[[:space:]].*$//'
  } | sort -u
}

main() {
  local files go_pkgs client_tests
  files="$(touched)"
  go_pkgs="$(grep -E '^src/server/.*\.go$' <<< "$files" | xargs -r -n1 dirname | sort -u | sed 's|^|./|' || true)"
  client_tests="$(grep -E '^src/client/.*\.test\.jsx?$' <<< "$files" || true)"
  if [ -z "$go_pkgs" ] && [ -z "$client_tests" ]; then
    echo "error: the series and overlay carry no tests" >&2
    return 1
  fi

  cd lib/dekart
  if [ -n "$go_pkgs" ]; then
    # shellcheck disable=SC2086  # one argument per package
    go vet $go_pkgs
    # shellcheck disable=SC2086
    go test $go_pkgs
  fi
  if [ -n "$client_tests" ]; then
    # shellcheck disable=SC2086  # one argument per test file
    npx vitest run $client_tests
  fi
}

main "$@"
