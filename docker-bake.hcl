target "docker-metadata-action" {}

// The upstream version we patch, never a default: `dekart_version` in .mise/lib.sh reads the submodule.
variable "VERSION" {
  default = ""
}

variable "SOURCE" {
  default = "https://github.com/astrateam-net/geoart"
}

group "default" {
  targets = ["image-local"]
}

// Upstream's own Dockerfile on the assembled tree: `mise run build:context` first, so the series
// and overlay are in lib/dekart before the context is sent. CI sets the other OCI labels.
target "image" {
  inherits = ["docker-metadata-action"]
  context  = "lib/dekart"
  labels = {
    "org.opencontainers.image.source" = "${SOURCE}"
  }
}

target "image-local" {
  inherits = ["image"]
  output   = ["type=docker"]
}

// Our Swarm nodes are amd64; Dekart's node build is slow under emulation.
target "image-all" {
  inherits  = ["image"]
  platforms = ["linux/amd64"]
}
