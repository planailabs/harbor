---
audience: developer
ordering_override: 50
---

# Testing & Provider Mocks

Developer reference for the Harbor test stack: three mock provider APIs,
Postgres-backed server tests, and the full-workload NixOS VM test. Everything
here runs offline — no real Cloudflare, Spaceship, or changedetection.io
account is touched.

## Mock provider APIs (`mocks/`)

Three stateful, in-memory axum servers, each faithful enough that the real
progenitor-generated client crates work against them unchanged:

| Crate | Mocks | Default `LISTEN` | Auth checked |
|-------|-------|------------------|--------------|
| `mock-spaceship` | Spaceship registrar API (availability, domain list/info, registration + async operations, nameservers, autorenew, contacts) | `127.0.0.1:8611` | `X-Api-Key` / `X-Api-Secret` |
| `mock-cloudflare` | Cloudflare v4 (accounts, zones, DNS records, registrar domain-check, Pages projects) with the full `{success, errors, result, result_info}` envelope | `127.0.0.1:8612` | `Authorization: Bearer` |
| `mock-changedetection` | changedetection.io (systeminfo, watch CRUD + tag filtering, tag CRUD) | `127.0.0.1:8613` | `x-api-key` |

Each crate exposes `pub fn router() -> axum::Router` for in-process use and a
binary that serves on `LISTEN`. Their `tests/client.rs` suites drive the real
`cloudflare-api` / `spaceship-api` / `changedetection-api` clients against the
mock — this is the schema-drift tripwire: if the mock and the generated client
disagree, deserialization fails in the test.

## Pointing the server at a mock

Two pieces, both test-only:

1. **Per-credential `api_url`** — cloudflare, spaceship, and changedetection
   credential JSON all accept an optional `api_url` key that overrides the
   production base URL (`server/src/credentials.rs`).
2. **`HARBOR_ALLOW_PRIVATE_APIS=1`** — the SSRF guard
   (`validate_outbound_url`) rejects loopback/private URLs by design; this
   environment variable is the escape hatch that lets credentials point at
   mocks on `127.0.0.1`. Never set it in production.

Related: `proxy.acme_directory_url` in the server config overrides the ACME
directory (defaults to Let's Encrypt production) so tests can issue real
certificates against a local [pebble](https://github.com/letsencrypt/pebble).

## Cargo test layers

```
cargo test --workspace --locked          # everything below
cargo test -p mock-cloudflare            # mock ↔ generated-client contract
cargo test -p harbor-server --features server   # Postgres-backed
```

The server's `credentials::pg_tests` boot a throwaway Postgres per test via
[`pgtemp`](https://docs.rs/pgtemp) (needs `initdb` on PATH — the flake dev
shell provides it), run the real `sqlx` migrations, insert encrypted
credentials whose `api_url` points at in-process mock routers, and assert the
credential → client → mock round-trip (including the Cloudflare account-id
backfill).

## Full-workload NixOS VM test (`tests/full.nix`)

```
nix build .#checks.x86_64-linux.full -L
```

One VM running the real deployment shape: PostgreSQL (auto-provisioned by
`server/module.nix`), `harbor-server`, the Pingora proxy, all three mocks
as systemd services, and pebble as ACME directory (its CA installed via
`security.pki.certificateFiles`; `PEBBLE_VA_ALWAYS_VALID=1` because the DNS-01
TXT record lands in the mock Cloudflare, which pebble cannot resolve).

The test script seeds an admin token, creates the three credentials over the
API, then exercises: spaceship availability + discovery, a Cloudflare zone +
DNS record round-trip (create → sync back → linked record), the
changedetection sub-URL watch flow, certificate issuance through pebble, and
proxy routing of the Harbor domain.

## CI

- **GitHub Actions** (`.github/workflows/rust.yml`): `test` runs the cargo
  suite in the flake dev shell; `nixos-test` enables KVM and builds the VM
  check.
- **GitLab CI** (`.gitlab-ci.yml`): `test` (cargo) and `flake-check`
  (`nix flake check -L --max-jobs 1`, which runs the same VM test serially).
