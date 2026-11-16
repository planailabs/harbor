---
audience: user
ordering_override: -34
---

# Edge Headers

The reverse proxy adds a fixed set of response headers to every response it
serves, whatever the upstream app does. They are applied at the edge because
that is the last hop a webspace cannot override.

| Header | Value | Notes |
|--------|-------|-------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | Only on HTTPS responses — browsers ignore it over plain HTTP. No `preload`: that is a zone-level decision. |
| `X-Content-Type-Options` | `nosniff` | |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | |
| `X-Frame-Options` | `DENY` | Only if the app set neither its own nor a CSP `frame-ancestors`. |
| `Content-Security-Policy` | `frame-ancestors 'none'` | Added as an *extra* header, unless the app's own CSP names `frame-ancestors`. Browsers intersect several CSP headers, so a webspace's own policy keeps working and framing is still blocked. |

`Server` from the upstream is dropped: an app's build string (for example a
container's nginx version) should not be readable from outside. So is the
upstream's `Alt-Svc`: which protocols reach a host is the edge's to say, and
an app's own value would name ports a visitor cannot use.

HTTPS responses carry `Alt-Svc: h3=":443"; ma=86400` (the port of
`https_addr`) while the HTTP/3 listener is running — see below.

Plain HTTP is not served at all: every request to a known host is answered with
`301` to the same path and query on `https://` before it reaches an upstream, so
nothing (an update feed's `manifest.json` in particular) can be fetched over the
clear. The `/.well-known/harbor.json` reachability marker and unknown hosts
are answered directly, since neither has an HTTPS origin to send a visitor to.

An app that already sends a stricter value of its own keeps it for
`X-Frame-Options`, and its CSP is intersected with the edge's `frame-ancestors`
rather than replaced.

An app that does want to be framed says by whom with its own CSP
`frame-ancestors` directive. The edge then adds neither framing header: its
`'none'` would cancel the app's list, and browsers ignore `X-Frame-Options`
once `frame-ancestors` is present.

## HTTP/3 (QUIC)

The proxy also speaks HTTP/3, on UDP at the same address and port as HTTPS
(normally 443), and is on by default. Browsers learn about it from the
`Alt-Svc` header on an HTTPS response and switch on later requests; anything
without QUIC keeps using HTTP/1.1 or HTTP/2 over TCP. The header is only sent
once the UDP socket is bound, so a host where it cannot listen keeps working
over TCP and never sends visitors to a dead port.

An HTTP/3 request goes through exactly the same routing, authentication,
headers and error pages as one over TCP — it is handed to the same proxy
handler, not to a second implementation — and reaches the upstream the same
way (HTTP/1.1 or HTTP/2, with the same `X-Forwarded-*` headers). The
certificates are the same too: whatever the sync task loads, including a
renewed certificate swapped in at runtime, serves both listeners. 0-RTT
(early data) is not accepted, since it can be replayed.

The same listener carries [WebTransport](/docs/webtransport) sessions to
hosts that declare a QUIC upstream.

To turn it off, set `quic = false` in the `[proxy]` section of the proxy's
config, or `services.harbor-proxy.quic = false` in NixOS (`proxy.quic` in the
server module's settings is passed on). With `openFirewall`, the module opens
UDP 443 alongside TCP 80/443 while QUIC is on. Other firewalls need UDP 443
open for HTTP/3 to be used.

How it is built: Pingora (0.8, and the current 0.9) has no QUIC listener.
QUIC comes from [quinn](https://github.com/quinn-rs/quinn) and the HTTP/3
framing from [h3](https://github.com/hyperium/h3); each HTTP/3 request stream
is wrapped as a Pingora custom downstream session (`proxy/src/quic.rs`) and
processed by the same `HttpProxy` as the TCP listener. QUIC's TLS 1.3 is
rustls, keyed from the same certificate store the BoringSSL listener uses.

## Per-folder settings

Each folder's page has a **Security Headers** card (not for Cloudflare Pages
folders, which the edge does not serve):

- **Edge headers** — on by default. Off sends the folder's responses out with
  only what the app set; the upstream `Server` banner is still dropped.
- **Allowed frame ancestors** — empty denies framing. A CSP source list
  (`https://cms.example.com 'self'`) is sent as `frame-ancestors <list>` in
  place of the `'none'` default, and `X-Frame-Options` is left out. Only
  `'self'`, `'none'` and scheme/host sources are accepted.

Both are fields on the folder's update endpoint too (`security_headers`,
`frame_ancestors`, `clear_frame_ancestors`), so a provisioning client can set
them when it creates the folder. Responses the edge renders itself — error
pages, redirects to HTTPS — always carry the full set.
