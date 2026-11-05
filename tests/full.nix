# NixOS integration test for the full Harbor workload on one machine:
#   1. PostgreSQL (auto-provisioned by the server module)
#   2. harbor-server (full dx build: web UI + REST/MCP API)
#   3. harbor-proxy (Pingora) fed by the server's internal API
#   4. mock-spaceship / mock-cloudflare / mock-changedetection provider APIs
#   5. pebble as a local ACME directory for real certificate issuance
#
# Credentials point at the mocks via their per-credential `api_url` override;
# HARBOR_ALLOW_PRIVATE_APIS=1 lets those loopback URLs through the SSRF
# guard (test-only escape hatch).
#
# ACME: the server's instant-acme client verifies TLS with rustls native roots.
# Point SSL_CERT_FILE directly at the pebble test CA so the test does not
# depend on the distro trust-store file layout inside the VM.
# PEBBLE_VA_ALWAYS_VALID=1 skips DNS-01 validation (the TXT record only lands
# in the mock Cloudflare API, which pebble cannot resolve).
#
# Run with:  nix build .#checks.x86_64-linux.full -L
{
  pkgs,
  ...
}:

let
  adminToken = "test-admin-token-abc123";
  # base64("0123456789abcdef0123456789abcdef") — fixed 32-byte AES key.
  encryptionKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

  webPort = 7380;
  proxyHttpPort = 8080;
  proxyHttpsPort = 8443;

  spaceshipPort = 8611;
  cloudflarePort = 8612;
  changedetectionPort = 8613;

  # Local test CA + "localhost" server certificate for pebble's HTTPS
  # directory endpoint (same pattern as mac-mgmt's tests/relay.nix). Long
  # validity because the derivation may be reused from a binary cache.
  pebbleTlsDir = pkgs.runCommand "pebble-test-tls" {} ''
    mkdir -p $out
    ${pkgs.openssl}/bin/openssl req -x509 -newkey rsa:2048 \
      -keyout $out/ca-key.pem \
      -out $out/ca-cert.pem \
      -days 3650 \
      -nodes \
      -subj "/CN=Harbor full test CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign"
    ${pkgs.openssl}/bin/openssl req -newkey rsa:2048 \
      -keyout $out/key.pem \
      -out $out/cert.csr \
      -nodes \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    ${pkgs.openssl}/bin/openssl x509 -req \
      -in $out/cert.csr \
      -CA $out/ca-cert.pem \
      -CAkey $out/ca-key.pem \
      -CAcreateserial \
      -out $out/cert.pem \
      -days 3650 \
      -copy_extensions copyall
    rm $out/cert.csr
  '';

  pebbleConfig = pkgs.writeText "pebble-config.json" (builtins.toJSON {
    pebble = {
      listenAddress = "127.0.0.1:14000";
      managementListenAddress = "127.0.0.1:15000";
      certificate = "${pebbleTlsDir}/cert.pem";
      privateKey = "${pebbleTlsDir}/key.pem";
      httpPort = 5002;
      tlsPort = 5001;
      ocspResponderURL = "";
      externalAccountBindingRequired = false;
    };
  });

  mockService = bin: port: {
    description = "${bin} provider API mock";
    wantedBy = [ "multi-user.target" ];
    environment.LISTEN = "127.0.0.1:${toString port}";
    serviceConfig = {
      ExecStart = "${pkgs.harbor-mocks}/bin/${bin}";
      DynamicUser = true;
      Restart = "on-failure";
    };
  };
in

pkgs.testers.nixosTest {
  name = "harbor-full";

  nodes.machine = { lib, ... }: {
    imports = [
      ../server/module.nix
    ];

    # The full server build serves a WASM web app and runs migrations at
    # boot; give the VM some headroom over the 1G default.
    virtualisation.memorySize = 3072;
    virtualisation.diskSize = 4096;

    # Trust the pebble directory certificate (see header comment).
    security.pki.certificateFiles = [ "${pebbleTlsDir}/ca-cert.pem" ];

    networking.firewall.enable = false;

    environment.systemPackages = [ pkgs.curl ];

    services.harbor-server = {
      enable = true;
      package = pkgs.harbor-server;
      settings = {
        web.port = webPort;
        local_hosting.dir = "/var/lib/harbor-server/web";
        secrets.encryption_key = encryptionKey;
        proxy = {
          domain = "harbor.test";
          acme_email = "admin@harbor.test";
          acme_directory_url = "https://localhost:14000/dir";
          http_addr = "127.0.0.1:${toString proxyHttpPort}";
          https_addr = "127.0.0.1:${toString proxyHttpsPort}";
        };
      };
    };

    # SSRF escape hatch: credentials in this test point api_url at loopback
    # mocks, which validate_outbound_url would otherwise reject.
    systemd.services.harbor-server.environment = {
      HARBOR_ALLOW_PRIVATE_APIS = "1";
      SSL_CERT_FILE = "${pebbleTlsDir}/ca-cert.pem";
    };

    services.harbor-proxy = {
      enable = true;
      package = pkgs.harbor-proxy;
    };

    systemd.services.mock-spaceship = mockService "mock-spaceship" spaceshipPort;
    systemd.services.mock-cloudflare = mockService "mock-cloudflare" cloudflarePort;
    systemd.services.mock-changedetection = mockService "mock-changedetection" changedetectionPort;

    systemd.services.pebble = {
      description = "pebble ACME test server";
      wantedBy = [ "multi-user.target" ];
      environment = {
        # Skip challenge validation entirely: the DNS-01 TXT record only
        # exists in the mock Cloudflare API, which pebble cannot query.
        PEBBLE_VA_ALWAYS_VALID = "1";
        PEBBLE_VA_NOSLEEP = "1";
      };
      serviceConfig = {
        ExecStart = "${pkgs.pebble}/bin/pebble -config ${pebbleConfig}";
        DynamicUser = true;
        Restart = "on-failure";
      };
    };
  };

  testScript = ''
    import hashlib
    import json
    import shlex

    API = "http://127.0.0.1:${toString webPort}"
    TOKEN = "${adminToken}"


    def dump_journals():
        for unit in [
            "harbor-server",
            "harbor-proxy",
            "pebble",
            "mock-spaceship",
            "mock-cloudflare",
            "mock-changedetection",
        ]:
            machine.log(f"--- journalctl -u {unit} (last 200 lines) ---")
            machine.log(
                machine.succeed(f"journalctl -u {unit} --no-pager -n 200 || true")
            )


    def api(method, path, body=None):
        cmd = (
            f"curl -sf --max-time 300 -X {method} "
            f"-H 'Authorization: Bearer {TOKEN}' -H 'Content-Type: application/json'"
        )
        if body is not None:
            cmd += " -d " + shlex.quote(json.dumps(body))
        cmd += f" {API}{path}"
        return machine.succeed(cmd)


    def api_json(method, path, body=None):
        return json.loads(api(method, path, body))


    machine.wait_for_unit("postgresql.service")
    for unit, port in [
        ("mock-spaceship", ${toString spaceshipPort}),
        ("mock-cloudflare", ${toString cloudflarePort}),
        ("mock-changedetection", ${toString changedetectionPort}),
        ("pebble", 14000),
    ]:
        machine.wait_for_unit(f"{unit}.service")
        machine.wait_for_open_port(port)
    machine.log("mocks and pebble are up")

    machine.wait_for_unit("harbor-server.service")
    machine.wait_for_open_port(${toString webPort})
    # The API index route needs no auth — use it as the readiness probe.
    machine.wait_until_succeeds(f"curl -sf {API}/api/v1 >/dev/null", timeout=300)
    machine.log("harbor-server API is up")

    # Seed an admin token (tokens.token_hash = hex(sha256(raw token))).
    token_hash = hashlib.sha256(TOKEN.encode()).hexdigest()
    machine.succeed(
        "sudo -u postgres psql -d harbor -c "
        f"\"INSERT INTO tokens (token_hash, kind, label) VALUES ('{token_hash}', 'admin', 'test-admin')\""
    )
    machine.log("admin token seeded")

    try:
        # ── Organization + credentials ────────────────────────────────
        org_id = api_json("POST", "/api/v1/organizations", {"name": "test-org"})

        cf_cred = api_json("POST", "/api/v1/credentials", {
            "organization_id": org_id,
            "name": "cf-mock",
            "credential_type": "cloudflare",
            "data_json": json.dumps({
                "api_token": "test-token",
                "api_url": "http://127.0.0.1:${toString cloudflarePort}",
            }),
        })
        ss_cred = api_json("POST", "/api/v1/credentials", {
            "organization_id": org_id,
            "name": "spaceship-mock",
            "credential_type": "spaceship",
            "data_json": json.dumps({
                "api_key": "test-key",
                "api_secret": "test-secret",
                "api_url": "http://127.0.0.1:${toString spaceshipPort}",
            }),
        })
        cd_cred = api_json("POST", "/api/v1/credentials", {
            "organization_id": org_id,
            "name": "cd-mock",
            "credential_type": "changedetection",
            "data_json": json.dumps({
                "api_key": "test-cd-key",
                "api_url": "http://127.0.0.1:${toString changedetectionPort}",
                "group": "testgroup",
            }),
        })

        # credential_test drives each mock through the server's own clients.
        for cred_id in [cf_cred, ss_cred, cd_cred]:
            status = api_json("POST", f"/api/v1/credentials/{cred_id}/test", {})
            assert status.startswith("OK"), f"credential {cred_id} test: {status}"
        machine.log("all three credentials verified against the mocks")

        # ── Spaceship: availability + discovery ───────────────────────
        avail = api_json("POST", "/api/v1/domains/check_availability", {
            "credential_id": ss_cred,
            "domain": "brand-new-site.com",
        })
        assert avail["available"] is True, f"unexpected availability: {avail}"
        assert avail["provider"] == "spaceship", f"unexpected provider: {avail}"

        ss_domains = api_json("POST", "/api/v1/domains/discover", {
            "credential_id": ss_cred,
            "organization_id": org_id,
        })
        assert ss_domains == [], f"fresh spaceship mock should be empty: {ss_domains}"
        machine.log("spaceship availability + discovery verified")

        # ── Cloudflare: zone + DNS record round-trip ──────────────────
        dom_id = api_json("POST", "/api/v1/domains", {
            "org_id": org_id,
            "domain_name": "example-full.test",
            "cf_credential_id": cf_cred,
            "registrar_type": "",
        })
        dom = api_json("GET", f"/api/v1/domains/{dom_id}")
        assert dom["cloudflare_zone_id"], f"no CF zone created: {dom}"

        sub_id = api_json("POST", "/api/v1/subdomains", {
            "domain_id": dom_id,
            "name": "www",
        })
        api("POST", "/api/v1/dns-records", {
            "domain_id": dom_id,
            "subdomain_id": sub_id,
            "record_type": "A",
            "record_value": "203.0.113.7",
            "proxied": False,
        })

        # Re-import records from the mock zone; the A record must round-trip.
        api("POST", f"/api/v1/domains/{dom_id}/sync_records", {})
        dom = api_json("GET", f"/api/v1/domains/{dom_id}")
        www = next((s for s in dom["subdomains"] if s["name"] == "www"), None)
        assert www is not None, f"www subdomain lost after sync: {dom}"
        a_records = [
            r for r in www["records"]
            if r["record_type"] == "A" and r["record_value"] == "203.0.113.7"
        ]
        assert a_records, f"A record did not round-trip through the mock: {www}"
        assert a_records[0]["cloudflare_record_id"], f"record not linked to CF: {a_records}"

        cf_domains = api_json("POST", "/api/v1/domains/discover", {
            "credential_id": cf_cred,
            "organization_id": org_id,
        })
        assert any(
            d["name"] == "example-full.test" and d["already_imported"]
            for d in cf_domains
        ), f"zone not discovered as imported: {cf_domains}"
        machine.log("cloudflare zone + DNS record round-trip verified")

        # ── ChangeDetection: bind credential + sub-URL watch flow ─────
        host_id = api_json("POST", "/api/v1/webspace-hosts", {
            "organization_id": org_id,
            "name": "site1",
            "kind": "proxy",
        })
        api("POST", f"/api/v1/changedetection/{host_id}/set", {"credential_id": cd_cred})
        cd_cfg = api_json("GET", f"/api/v1/changedetection/{host_id}")
        assert cd_cfg["credential_id"] == cd_cred, f"credential not bound: {cd_cfg}"

        suburl_id = api_json(
            "POST", f"/api/v1/changedetection/{host_id}/suburl_create", {"path": "/pricing"}
        )
        suburls = api_json("POST", f"/api/v1/changedetection/{host_id}/suburls", {})
        assert any(
            s["id"] == suburl_id and s["path"] == "/pricing" for s in suburls
        ), f"sub-URL missing: {suburls}"
        machine.log("changedetection credential binding + sub-URL flow verified")

        # The ACME path contacts the local proxy for HTTP/DNS challenge plumbing;
        # prove the proxy is ready before certificate issuance so startup
        # failures are reported at the right boundary.
        machine.wait_for_unit("harbor-proxy.service")
        machine.wait_for_open_port(${toString proxyHttpPort})

        # Served by the proxy itself on any host — proves Pingora is up.
        well_known = json.loads(machine.succeed(
            "curl -sf http://127.0.0.1:${toString proxyHttpPort}/.well-known/harbor.json"
        ))
        assert well_known["service"] == "harbor-proxy", f"unexpected: {well_known}"
        machine.log("proxy is up")

        # ── ACME: issue a real certificate via pebble ─────────────────
        # The domain has a mock CF zone, so the DNS-01 TXT record is written
        # to the mock; pebble validates instantly (PEBBLE_VA_ALWAYS_VALID).
        issue = api_json("POST", "/api/v1/certificates/issue", {"domain": "example-full.test"})
        assert issue == "issued", f"cert issuance failed: {issue}"

        certs = api_json("GET", "/api/v1/certificates")
        cert = next((c for c in certs if c["domain"] == "example-full.test"), None)
        assert cert is not None, f"no certificate row: {certs}"
        assert cert["acme_status"] == "valid", f"cert not valid: {cert}"
        assert cert["issuer"] == "letsencrypt", f"unexpected issuer: {cert}"
        machine.log("ACME certificate issued through pebble")

        # ── Proxy routing ─────────────────────────────────────────────

        # The Harbor route is synced from the server's internal API; once it
        # lands, requests for the Harbor domain reach the server upstream.
        machine.wait_until_succeeds(
            "curl -sf -H 'Host: harbor.test' "
            "http://127.0.0.1:${toString proxyHttpPort}/api/v1 >/dev/null",
            timeout=120,
        )
        machine.log("proxy answers and routes the Harbor domain to the server")

        machine.log("full Harbor workload test passed!")
    except Exception:
        dump_journals()
        raise
  '';
}
