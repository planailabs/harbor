---
audience: user
ordering_override: -37
---

# WebTransport

Browsers can open [WebTransport](https://www.w3.org/TR/webtransport/) sessions
(`new WebTransport("https://app.example.com/...")`) to a proxy host, with
streams in both directions and unreliable datagrams. The Harbor edge accepts
the session on its [HTTP/3 listener](/docs/edge-headers), opens a session of
its own to the host's upstream, and relays between the two.

## Turning it on for a host

A proxy host offers WebTransport once it has a **QUIC upstream**. Set it when
creating or updating the host (REST `create_host` / `update_host_settings`,
the same fields in the MCP tools):

```json
{
  "quic_upstream": {
    "port": 4433,
    "spki_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  }
}
```

- `port`: the UDP port of the upstream's WebTransport (HTTP/3) listener. The
  address is the host's existing upstream, the host part of its folders'
  upstream (a tunnel URL or local port), for example the instance's IPv6
  address.
- `spki_sha256`: the lowercase hex SHA-256 of the upstream certificate's DER
  **SubjectPublicKeyInfo**, i.e. of its public key, not of the certificate.

`get_host` returns the field (`null` when unset). On update, an object sets
it, `null` removes it, and leaving the field out keeps it. Without a QUIC
upstream, a WebTransport request to the host is answered `501`; HTTP is not
affected either way.

To compute the pin from the upstream's certificate:

```sh
openssl x509 -in cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER | sha256sum
```

## Trust: a pinned key, not a CA

The upstream presents a short-lived self-signed certificate (browsers that
connect to it directly need one valid for at most 14 days, so it rotates).
The edge does not check a CA, the name, or the validity period. It accepts
exactly a certificate whose public key hashes to `spki_sha256`, and the TLS
handshake still proves that the upstream holds that key. Rotating the
certificate on the same key needs no change in Harbor; changing the key
means updating the pin. With a wrong pin, the edge refuses to reach the
upstream and answers the browser `502`.

## What the edge does with a session

1. The browser's extended CONNECT (`:protocol = webtransport`) goes through
   the same routing and checks as any request to the host: unknown hosts,
   redirect domains, folder matching, basic-auth and OIDC gates. A folder's
   mount prefix is stripped from the path as for HTTP. Browsers send no
   cookies with WebTransport, so a folder behind a basic-auth or OIDC gate
   refuses it; authorize in the upstream (the ticket below) instead.
2. The edge opens its own session to the upstream with the same path and
   query (an instance authorizes with a single-use ticket in the query), the
   browser's `Origin`, `Cookie`, `Authorization` and `User-Agent`, and the
   edge's `X-Forwarded-For` / `-Proto` / `-Host`. The browser gets the
   upstream's answer: its status when it refuses (for example `403` for a
   spent ticket), `502` / `504` when it cannot be reached, and `200` only
   once the upstream accepted.
3. From then on it relays 1:1. Every unidirectional and bidirectional stream
   either side opens is mirrored and piped both ways. A stream reset
   (`RESET_STREAM`) and a `STOP_SENDING` are passed on with their application
   error codes, so a superseded media stream can be reset end to end.
   Datagrams are forwarded as they arrive, and one that the other side cannot
   take at that moment is dropped, never queued. Closing the session with a
   code and reason closes the other side with the same code and reason. The
   edge buffers nothing beyond QUIC flow control and reorders nothing.

Limits: one session per QUIC connection, which is how browsers open them
(the default, `allowPooling: false`). A `STOP_SENDING` from the browser on a
stream the upstream is writing reaches the upstream with the next data on
that stream. 0-RTT is not accepted.

## Implementation

`proxy/src/webtransport.rs`. The browser side uses `h3`'s own extension
crates (h3-webtransport, h3-datagram), because it shares connections with
ordinary HTTP/3; the upstream side uses web-transport-quinn's client. Two
crates are vendored under `proxy/vendor/` with small fixes, each described
in its `Cargo.toml`:

- `h3`: decodes a stream header that is already buffered instead of waiting
  for more data. Without the fix, a uni stream whose header arrived together
  with its data stalled, and a reset on it was lost.
- `h3-webtransport`: makes the CONNECT stream accessible, so the edge can read
  and write the session's close capsule.

`proxy/tests/webtransport.rs` runs a client through the real binary to a
WebTransport echo server with a self-signed certificate. It checks uni and
bidi streams, datagrams, resets and closes in both directions, the upstream's
refusal, a wrong pin and a host without a QUIC upstream.
