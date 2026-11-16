-- WebTransport through the edge: where a proxy host's sessions are re-opened
-- (this UDP port on its folders' upstream host) and the only public key that
-- upstream may present (lowercase hex SHA-256 of its certificate's DER
-- SubjectPublicKeyInfo; the certificate itself is self-signed and rotates).
-- Both or neither: without them the edge refuses WebTransport to the host.
ALTER TABLE webspace_hosts ADD COLUMN quic_upstream_port INTEGER
    CHECK (quic_upstream_port BETWEEN 1 AND 65535);
ALTER TABLE webspace_hosts ADD COLUMN quic_upstream_spki_sha256 TEXT
    CHECK (quic_upstream_spki_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE webspace_hosts ADD CONSTRAINT webspace_hosts_quic_upstream_complete
    CHECK ((quic_upstream_port IS NULL) = (quic_upstream_spki_sha256 IS NULL));
