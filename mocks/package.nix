{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "harbor-mocks";
  version = "0.1.0";
  src = ../.;
  cargoLock.lockFile = ../Cargo.lock;
  cargoLock.outputHashes = import ../extra-hashes.nix;

  cargoBuildFlags = [
    "-p" "mock-spaceship"
    "-p" "mock-cloudflare"
    "-p" "mock-changedetection"
  ];

  doCheck = false;

  meta = {
    description = "Harbor provider API mocks – Spaceship, Cloudflare and ChangeDetection.io";
    license = lib.licenses.asl20;
  };
}
