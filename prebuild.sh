#!/usr/bin/env bash
#
# Fill the xzar cache with what CI is about to need: the dev shell every job
# runs in, the runner image itself, and the Rust packages, which the flake
# check would otherwise build again.
#
# Needs XZAR_TOKEN, which only protected pipelines get — an unprotected
# branch skips the job rather than failing it.
set -euo pipefail

cd "$(dirname "$0")"

if [ -z "${XZAR_TOKEN:-}" ]; then
  echo "XZAR_TOKEN is not set; skipping the cache prebuild."
  echo "That is expected on a pipeline without protected variables."
  exit 0
fi

xzar config add-server planai https://xzar.plan.ai "$XZAR_TOKEN"

upload() {
  # The cache refuses now and then under load; the job is cheap to retry and
  # expensive to lose.
  while ! xzar --server planai upload --pin "$1" --desc "$(readlink -f "$2")" --leave-after-abandon 1m "$2"; do true; done
}

build() {
  nix build ".#$1" -o "result-$2"
  upload "harbor/$2" "result-$2"
  rm -f "result-$2"
}

build devShells.x86_64-linux.default devshell
build image image
build harbor-server server
build harbor-proxy proxy
build harbor-mocks mocks
