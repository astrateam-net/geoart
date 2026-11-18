target "docker-metadata-action" {}

// Ours, never a default: `geoart_version` in .mise/lib.sh derives it from the submodule.
variable "VERSION" {
  default = ""
}

variable "SOURCE" {
  default = "https://github.com/astrateam-net/geoart"
}

group "default" {
  targets = ["image-local"]
}

// Upstream's own Dockerfile on the assembled tree: `mise run up` first, so the series and
// overlay are in lib/dekart before the context is sent.
target "image" {
  inherits = ["docker-metadata-action"]
  context  = "lib/dekart"
  labels = {
    "org.opencontainers.image.source"  = "${SOURCE}"
    "org.opencontainers.image.version" = "${VERSION}"
    "org.opencontainers.image.title"   = "geoart"
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
