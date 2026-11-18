#!/usr/bin/env bash
#MISE description="Assemble the docker build context: the patched tree plus what upstream's CI writes"
#MISE dir="{{config_root}}"
#MISE depends=["up"]
set -Eeuo pipefail

# Upstream's Dockerfile copies .npmrc, which its CI writes with a GitHub Packages token. The
# pinned lockfile resolves from registry.npmjs.org only, so an empty file is enough.
[ -e lib/dekart/.npmrc ] || : > lib/dekart/.npmrc
