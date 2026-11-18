#!/usr/bin/env bash
#MISE alias="build"
#MISE description="Build the image of the assembled tree and run its structure tests"
#MISE dir="{{config_root}}"
#MISE depends=["build:context"]
set -Eeuo pipefail

# shellcheck source=../../lib.sh
source .mise/lib.sh

main() {
  # The tag is the upstream version we patch, as the containers repo tags its images.
  VERSION="$(dekart_version)"
  export VERSION
  echo "geoart ${VERSION}"

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
