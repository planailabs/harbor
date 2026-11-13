{
  lib,
  rustPlatform,
  cmake,
  clang,
  libclang,
  perl,
  git,
}:

rustPlatform.buildRustPackage {
  pname = "harbor-proxy";
  version = "0.1.0";
  src = import ../src.nix { inherit lib; };
  cargoLock.lockFile = ../Cargo.lock;
  cargoLock.outputHashes = import ../extra-hashes.nix;

  cargoBuildFlags = [ "-p" "harbor-proxy" ];

  nativeBuildInputs = [
    cmake   # boring-sys builds BoringSSL from source
    clang   # C/C++ compiler for BoringSSL
    perl    # BoringSSL build scripts need perl
    git     # boring-sys runs `git init` to apply patches to vendored BoringSSL
  ];

  env.LIBCLANG_PATH = "${libclang.lib}/lib";

  # nixpkgs' cargoSetupHook appends its `cargoUseSystemLibs` preConfigure hook
  # by default, which exports ZSTD_SYS_USE_PKG_CONFIG / AWS_LC_SYS_USE_SYSTEM /
  # LIBGIT2_NO_VENDOR / ... and makes every -sys crate probe pkg-config for a
  # system copy. This derivation intentionally builds those C dependencies from
  # the vendored sources (BoringSSL via cmake/clang, bundled zstd), so keep the
  # vendored behaviour instead of adding a pkg-config/zstd/aws-lc dependency
  # set that the crate graph does not otherwise need.
  dontCargoUseSystemLibs = true;

  doCheck = false;

  meta = {
    description = "Harbor reverse proxy – Pingora-based TLS termination and routing";
    license = lib.licenses.asl20;
    mainProgram = "harbor-proxy";
  };
}
