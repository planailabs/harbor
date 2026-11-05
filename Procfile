server: cd server && RUST_LOG=debug DEV_ONLY_NO_AUTH=1 dx serve | tee /tmp/harbor-proxy.log
proxy: CONFIG_PATH=$PWD/config.toml RUST_LOG=debug cd proxy && cargo watch -- sudo env LIBCLANG_PATH=$LIBCLANG_PATH CARGO_TARGET_DIR=/tmp/proxy cargo run | tee /tmp/harbor-server.log
tailwind: cd server && npm run tailwind
