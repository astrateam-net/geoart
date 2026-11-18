#!/usr/bin/env bash
set -euo pipefail

# git hands a hook an absolute GIT_DIR, and in a linked worktree that makes
# `git -C lib/dekart` read the outer index. Every call here names its repo.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY

pushd() {
  builtin pushd "$@" > /dev/null
}

popd() {
  builtin popd > /dev/null
}

dekart_version() {
  jq -r .version lib/dekart/package.json
}

# Dekart 0.27.0 releases as 27.0.0; the last slot is ours ($1).
# Not `git describe`: actions/checkout fetches submodules shallow and untagged.
geoart_version() {
  local version patch
  version="$(dekart_version)"
  patch="${1:-0}"
  echo "${version#*.}.${patch}"
}

# Upstream's toolchain, read from what its own build uses.
dekart_go_version() {
  sed -n 's/^go //p' lib/dekart/go.mod
}

dekart_node_version() {
  sed -n 's/^FROM node:\([0-9][0-9.]*\).*/\1/p' lib/dekart/Dockerfile | head -1
}

os() {
  osname=$(uname | tr '[:upper:]' '[:lower:]')
  case $osname in
    linux)
      ldd_output=$(ldd --version 2>&1 || true)
      if echo "$ldd_output" | grep -iq musl; then
        osname="alpine"
      fi
      ;;
    darwin) osname="macos" ;;
    cygwin* | mingw*) osname="windows" ;;
  esac
  echo "$osname"
}

arch() {
  cpu="$(uname -m)"
  case "$cpu" in
    aarch64) cpu=arm64 ;;
    x86_64) cpu=amd64 ;;
  esac
  echo "$cpu"
}

if [[ ! ${ARCH-} ]]; then
  ARCH=$(arch)
  export ARCH
fi

if [[ ! ${OS-} ]]; then
  OS=$(os)
  export OS
fi

if [[ ! ${RELEASE_PATH-} ]]; then
  RELEASE_PATH="dist"
  export RELEASE_PATH
fi

run-steps() {
  local -i failed=0
  mkdir -p .cache
  rm -f .cache/checklist
  while (($#)); do
    local name=$1
    shift
    local fn=$1
    shift
    echo "$name..."
    if [[ $failed == 0 ]]; then
      if $fn | indent; then
        echo "- [X] $name" >> .cache/checklist
      else
        ((failed++))
        echo "- [-] $name" >> .cache/checklist
        echo "Failed" | indent
      fi
    else
      echo "- [ ] $name" >> .cache/checklist
      echo "Skipped" | indent
    fi
  done
  if [[ $failed != 0 ]]; then
    return 1
  fi
}

quiet() {
  "$@" > /dev/null
}

indent() {
  local count=2
  local space
  space=$(printf "%${count}s")
  sed "s/^/$space| /g"
}
