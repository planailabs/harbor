{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "harbor-mocks";
  version = "0.1.0";
  src = import ../src.nix { inherit lib; };
  cargoLock.lockFile = ../Cargo.lock;
  cargoLock.outputHashes = import ../extra-hashes.nix;

  cargoBuildFlags = [
    "-p" "mock-spaceship"
    "-p" "mock-cloudflare"
    "-p" "mock-changedetection"
  ];

  # See proxy/package.nix: nixpkgs' default `cargoUseSystemLibs` preConfigure
  # hook switches -sys crates to system libraries (pkg-config probing), while
  # this workspace builds them from the vendored sources.
  dontCargoUseSystemLibs = true;

  doCheck = false;

  meta = {
    description = "Harbor provider API mocks – Spaceship, Cloudflare and ChangeDetection.io";
    license = lib.licenses.asl20;
  };
}
