{
  lib,
  rustPlatform,
  fetchurl,
  pkg-config,
  openssl,
  dioxus-cli-patched,
  nodejs,
  wasm-bindgen-cli_0_2_121,
  binaryen,
  tailwindcss_3,
  lld,
  wrangler,
  makeWrapper,
  gitSha ? "unknown",
}:

let
  # utoipa-swagger-ui's build.rs downloads Swagger UI with curl unless this
  # env var points it at a local file (same fix as mac-mgmt's server/package.nix).
  swagger-ui = fetchurl {
    url = "https://github.com/swagger-api/swagger-ui/archive/refs/tags/v5.17.14.zip";
    hash = "sha256-SBJE0IEgl7Efuu73n3HZQrFxYX+cn5UU5jrL4T5xzNw=";
  };
in

rustPlatform.buildRustPackage {
  pname = "harbor-server";
  version = "0.1.0";
  src = ../.;
  cargoLock.lockFile = ../Cargo.lock;
  cargoLock.outputHashes = import ../extra-hashes.nix;

  cargoBuildFlags = [ "-p" "harbor-server" ];

  nativeBuildInputs = [
    pkg-config
    dioxus-cli-patched
    nodejs
    wasm-bindgen-cli_0_2_121
    binaryen
    tailwindcss_3
    lld
    makeWrapper
  ];

  buildInputs = [
    openssl
  ];

  SWAGGER_UI_DOWNLOAD_URL = "file://${swagger-ui}";
  env.GIT_SHA = gitSha;

  doCheck = false;

  # Build with dx instead of cargo so assets and WASM are bundled
  buildPhase = ''
    runHook preBuild

    # Tailwind CSS
    pushd server
    npm run tailwind:build
    popd

    dx build --release --fullstack --package harbor-server

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin $out/share
    cp -r target/dx/harbor-server/release/web $out/share/harbor-server

    # Wrap the binary so wrangler is on PATH (needed for Pages deployments)
    if [ -e $out/share/harbor-server/harbor-server ]; then
      makeWrapper $out/share/harbor-server/harbor-server $out/bin/harbor-server \
        --prefix PATH : ${lib.makeBinPath [ wrangler ]}
    else
      makeWrapper $out/share/harbor-server/server $out/bin/harbor-server \
        --prefix PATH : ${lib.makeBinPath [ wrangler ]}
    fi

    runHook postInstall
  '';

  meta = {
    description = "Harbor server – domain, DNS, and Cloudflare Pages management";
    license = lib.licenses.asl20;
    mainProgram = "harbor-server";
  };
}
