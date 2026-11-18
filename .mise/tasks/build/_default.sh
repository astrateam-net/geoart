#!/usr/bin/env bash
#MISE alias="build"
#MISE description="Build the image of the assembled tree and run its structure tests"
#MISE dir="{{config_root}}"
#MISE depends=["build:context"]
#USAGE arg "[patch]" default="0" help="Our release slot: the N in 27.0.N"
set -Eeuo pipefail

# shellcheck source=../../lib.sh
source .mise/lib.sh

main() {
  VERSION="$(geoart_version "${usage_patch:-0}")"
  export VERSION
  echo "geoart ${VERSION} (Dekart $(dekart_version))"

  mkdir -p .cache
  docker buildx bake --metadata-file .cache/docker-bake.json image-local

  # bake targets carry no tags, so the fresh image is addressed by digest; the containerd image
  # store reports it as containerimage.digest, the classic store as containerimage.config.digest.
  local image
  image="$(jq -r '."image-local" | ."containerimage.digest" // ."containerimage.config.digest"' .cache/docker-bake.json)"
  docker tag "$image" "geoart:${VERSION}"
  container-structure-test test --image "geoart:${VERSION}" --config tests.yaml
}

main "$@"
