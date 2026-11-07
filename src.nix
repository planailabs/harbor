# The workspace as the Rust packages build it: every member (cargo loads
# them all) and nothing else, so a commit to CI, docs, tests or scripts does
# not rebuild them.
{ lib }:

lib.fileset.toSource {
  root = ./.;
  fileset = lib.fileset.unions [
    ./Cargo.toml
    ./Cargo.lock
    ./common
    ./design
    ./changedetection-api
    ./cloudflare-api
    ./dataforseo-api
    ./spaceship-api
    ./mocks
    ./proxy
    ./server
    ./upload-cli
  ];
}
