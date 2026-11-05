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
container's nginx version) should not be readable from outside.

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
