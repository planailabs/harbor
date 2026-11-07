{
  inputs = {
    # Include git submodules (common, design) in the flake source.
    self.submodules = true;

    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    gitlab-incus-image.url = "git+https://git.mkg20001.io/mkg20001/gitlab-incus-image.git";
    gitlab-incus-image.inputs.nixpkgs.follows = "nixpkgs";
    gitlab-nix-ci.url = "git+https://git.mkg20001.io/mkg20001/gitlab-nix-ci.git";
    gitlab-nix-ci.inputs.nixpkgs.follows = "nixpkgs";
    gitlab-nix-ci.inputs.gitlab-incus-image.follows = "gitlab-incus-image";
    xzar.url = "github:mkg20001/xzar";
    xzar.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, gitlab-incus-image, gitlab-nix-ci, xzar, ... }:
    {
      overlays.default = import ./overlay.nix { gitSha = self.rev or self.dirtyRev or "unknown"; };
      nixosModules.default = import ./server/module.nix;
      nixosModules.harbor = import ./server/module.nix;
      nixosModules.harbor-proxy = import ./proxy/module.nix;
    } //
    flake-utils.lib.eachDefaultSystem (system:
      let
        gitSha = self.rev or self.dirtyRev or "unknown";
        overlays = [
          (import rust-overlay)
          (import ./overlay.nix { inherit gitSha; })
          xzar.overlays.default
        ];
        pkgs = import nixpkgs { inherit system overlays; };
        toolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
          targets = [ "wasm32-unknown-unknown" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            toolchain
            cargo-edit
            cargo-watch

            # Dioxus CLI (patched with --skip-platform-features)
            dioxus-cli-patched

            # Build dependencies
            pkg-config
            openssl
            nodejs
            tailwindcss_3

            # Ephemeral test databases (pgtemp spawns initdb/postgres)
            postgresql

            # cargo-progenitor installed via: cargo install cargo-progenitor
            wrangler

            # proxy (BoringSSL build via boring-sys)
            cmake
            clang
            libclang.lib
            perl

            # For WASM
            wasm-bindgen-cli_0_2_121
            binaryen  # wasm-opt
            lld
          ];

          RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
        };

        packages = {
          default = pkgs.harbor-server;
          harbor-server = pkgs.harbor-server;
          harbor-proxy = pkgs.harbor-proxy;
          harbor-mocks = pkgs.harbor-mocks;
          dioxus-cli-patched = pkgs.dioxus-cli-patched;
        } // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          # NixOS-in-Incus image for the plan.ai `nix-image` GitLab runners. The
          # custom executor builds `flake#image` to obtain the job rootfs; without
          # this output every job fails in prepare_executor with "flake does not
          # provide attribute ... 'image'". Mirrors the mac-mgmt / node-mgmt /
          # memvault CI image: nix with the xzar binary cache preconfigured, plus
          # the tooling the pipeline scripts rely on.
          image = (nixpkgs.lib.nixosSystem {
            system = "x86_64-linux";
            modules = [
              "${nixpkgs}/nixos/modules/virtualisation/lxc-container.nix"
              gitlab-incus-image.nixosModules.gitlab-incus-image
              # Every Rust build in a job reuses the crates earlier jobs
              # compiled, from the job's /cache volume.
              gitlab-nix-ci.nixosModules.cargo-target-cache
              ({ pkgs, ... }: {
                gitlab-nix-ci.cargoTargetCache.enable = true;

                # `cargo test` in the `test` job runs harbor-server's
                # `credentials::pg_tests`, which boot an ephemeral PostgreSQL
                # cluster through the `pgtemp` crate. pgtemp refuses to run
                # Postgres as root: when euid == 0 it `chown -R`s the data dir
                # to, and then execs `initdb`/`postgres` as, the `postgres`
                # user (via `sudo`). The `nix-image` job runs as root in this
                # rootfs, so it must provide both. Pulling `postgresql` into
                # the devShell (see devShells.default) ships the binaries but
                # no OS user, unlike a distro package which creates one.
                # Without this, every pg_test aborts with
                # `chown: invalid user: 'postgres'`.
                users.groups.postgres = { };
                users.users.postgres = {
                  isSystemUser = true;
                  group = "postgres";
                  home = "/var/lib/postgresql";
                  createHome = true;
                };

                environment.systemPackages = with pkgs; [
                  openssh
                  rsync
                  pkgs.xzar-client
                  pixz
                  # pgtemp shells out to `sudo -u postgres` when running as root.
                  sudo
                ];

                nixpkgs.overlays = [
                  xzar.overlays.default
                ];

                programs.git.config.advice.detachedHead = false;

                nix.settings = {
                  substituters = [
                    "https://xzar.plan.ai"
                  ];
                  trusted-public-keys = [
                    "xzar.plan.ai:KUE66pjr6UX5HHCn9kedN1DJ2J5nSlBrKmE7tUjXewE="
                  ];
                };
              })
            ];
          }).config.system.build.gitlab-incus-image;
        };

        # nixpkgs.lib (not pkgs.lib): evaluating pkgs for unsupported systems
        # (x86_64-darwin) throws, and `nix flake show` walks every system.
        checks = nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          # Full-workload NixOS VM test: server + proxy + postgres + provider
          # mocks + pebble ACME. Run with:
          #   nix build .#checks.x86_64-linux.full -L
          full = pkgs.callPackage ./tests/full.nix { };
        };
      });
}
