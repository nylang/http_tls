# http_tls

Optional MIT-licensed connected HTTPS adapter for Nyra. Import
`http_tls:http_tls.ny` together with the public http, tls and net_core barrels.
This package owns no HTTP grammar or crypto implementation. It composes
`HttpClientExchange` with `TlsStream` using the TLS package's pinned OpenSSL 3.5.9
native inputs. Plain http consumers do not depend on this package or TLS.

`HttpsClient.New(connection, config, head, body, limits, options)` validates the
request, explicit CA configuration, Host/peer identity and ALPN before adopting
TCP on success. DNS names compare by ASCII case; IP literals compare by address,
including alternate IPv6 spelling. URL/IDNA/trailing-dot normalization is outside
this connected API. Empty or http/1.1 ALPN configuration offers http/1.1; negotiated
absence or http/1.1 is accepted before sending HTTP bytes.

Repeated `Next()` calls drive TLS Futures/Poll synchronously on the caller thread
and return shared owned HTTP events. One copied absolute deadline/shared token
covers handshake, upload, response and explicit `Shutdown()`. Pass original dial
options to include connection establishment in the same budget. TLS errors retain
their original typed stream cause and accepted plaintext progress; raw EOF is
never converted into authenticated close_notify. EOF-delimited responses require
authenticated closure. Fixed/chunked HTTP framing may complete before TLS closes.

Successful completion remains observable until Close/Shutdown. Call `Shutdown()`
after HTTP completion for bidirectional close_notify under the original controls;
`Close()` and drop abort without waiting. Returned HTTP metadata/body owners
survive client retirement. Connections are single-request and never reused.
Requests use bounded immutable bodies; responses stream in at most 16 KiB chunks.
Expect gating, early-final upload handling, CONNECT, upgrade/tunnel ownership,
Automatic redirect following is available through the separate facade below;
pooling remains outside the connected client.

## Opening an HTTPS URL

`HttpsClient.Open(url, config, verb, fields, body, limits, resolver, dial, options)`
accepts only a validated https `HttpUrl`. It derives Host, origin target and
certificate/SNI peer name from that URL. Config peer_name may be empty or match
that host; a conflicting peer or non-http/1.1 ALPN fails before DNS/connect.
Explicit CA trust remains required; TLS validates its configuration before
adopting the connected TCP socket. DNS/connection failures remain original
network errors inside HttpsClientError, with Resolve/Connect stage and zero
HTTP progress. No HTTP bytes precede verified TLS handshake completion.

The shared [URL/dial policy](https://github.com/nylang/http/blob/main/README.md#absolute-urls-and-opening-connections)
uses a caller-owned bounded AsyncResolver and a private call-local readiness
loop. One original deadline/token passes through DNS, sequential connection
attempts, handshake, request/response and explicit Shutdown. Numeric URLs bypass
DNS. No downgrade, proxy, redirect or pool is implied by Open.

The [URL acceptance](https://github.com/nylang/http/blob/main/docs/url-acceptance-2026-10-27.json) adds URL-based
live opens and controlled blocked-DNS/admission cases to the connected-client
foundation: 35 ordinary HTTPS scenarios plus 11 URL/DNS failure scenarios per
accepted desktop host. Test-only resolver hooks are linked only into a separate
failure consumer; production and ordinary live consumers retain ordinary inputs.

Run the sibling [HTTP acceptance runner](https://github.com/nylang/http/blob/main/scripts/accept_clients.py) with
`--http-tls ../http_tls --tls ../tls --openssl-root /path/to/openssl-3.5.9`.
The [client receipt](https://github.com/nylang/http/blob/main/docs/client-acceptance-2026-10-27.json) binds this
adapter and all dependencies to tested desktop source-candidate compilers and
public SDK runtimes; it includes 29 HTTPS scenarios per host and production
fixture isolation. See [HTTP test scope](https://github.com/nylang/http/blob/main/tests/README.md) and
[TLS native setup](https://github.com/nylang/tls/blob/main/README.md) for linking and remaining acceptance limits.

This is an independent public Git repository at
<https://github.com/nylang/http_tls>. Source availability does not imply a tagged
binary/package release or new acceptance. The automatic-follow increment records
public SDK 1.0.2 acceptance on all four desktop hosts; mobile execution remains
open. Existing acceptance receipts retain their original source identities.

## Redirect snapshots

The shared http package now supplies relative `HttpUrl.Resolve` and an explicit
`HttpRedirectChain`. After an accepted `Follow(head)`, Close the old client without
draining/reusing its body, then call `HttpsClient.OpenRequest(snapshot, config,
resolver, dial)` for an https snapshot. The URL supplies this hop's Host and SNI/
certificate identity; peer_name may be empty or match this hop. The snapshot
retains original limits/deadline/shared token. Plain snapshots use `OpenTcp`.
The coordinator never downgrades HTTPS, and requires separate opt-ins for
cross-origin follows and preserved unsafe method/body replay. It filters fields
before exposing the next request; returning to the original origin cannot
restore stripped credentials. These snapshot methods retain explicit transport selection. The automatic
facade below composes the same coordinator and transport paths. On a terminal response, keep consuming its
body and call Shutdown normally. See [policy and usage](https://github.com/nylang/http/blob/main/README.md#explicit-redirects-and-replay-requests)
and [redirect acceptance](https://github.com/nylang/http/blob/main/docs/redirect-acceptance-2026-10-27.json).

## Automatic redirects

`HttpFollowClient.New(url, config, verb, fields, body, limits, policy, dial, options)`
validates and retains a request without network I/O. `Next(resolver)` borrows the
caller's bounded resolver and selects plain TCP or verified TLS from the current
URL. Keep using the same resolver pool. Dial settings and the original absolute
deadline/shared cancellation apply across every hop; no timeout is refreshed.
The facade belongs to this optional adapter so HTTP's protocol/TCP package keeps
its TLS-free dependency graph.

Accepted redirects are followed internally: close the old connection without
draining its body, then open the next owned snapshot. The shared redirect policy
controls hop limits, cross-origin filtering, GET rewrites and unsafe replays.
HTTP to HTTPS requires the cross-origin opt-in; HTTPS to HTTP is always rejected.
No transport failure is retried. Informational events remain observable with
`Url()` and `RedirectCount()`; followed response heads and bodies are suppressed.
The terminal head, streamed body and trailers use the existing owned event API.

TLS configuration strings are copied at construction. Leave `peer_name` empty to
derive certificate/SNI identity from each URL; a fixed peer must match every
HTTPS hop. Explicit PEM CA trust and HTTP/1.1 ALPN rules remain unchanged. Failures
retain exactly one original HTTP/TCP or HTTPS error, hop URL/count and committed
per-hop progress. Counts are not aggregate or peer-delivery attestations.

Completion is durable until explicit retirement. `TrailerCount/TrailerAt` expose
only the completed terminal response; pending/index queries do not poison the
cursor. `Shutdown()` after completion closes TCP or completes TLS close_notify
under the original controls. Close/drop abort immediately. No pooling, streaming
request producer, proxy, IDNA or upgrade/tunnel handling is added.

Run `../http/scripts/accept_follow.py` with `--sdk`, `--compiler`,
`--openssl-root` and an external `--out-dir`. It repeats the core, live-client,
controlled-DNS and explicit-redirect suites before automatic TCP/HTTPS cases and
a TCP-to-TLS transition with exact request and old-connection retirement checks.


[H3d desktop acceptance](https://github.com/nylang/http/blob/main/docs/follow-acceptance-2026-10-28.json)
passes with exact public SDK 1.0.2 compilers/runtimes on macOS arm64, Linux
x86_64, Windows x86_64 and physical Intel macOS x86_64. Every host passes 76 core
cases and 76 isolated replays, 82 baseline network/control scenarios, 25 explicit
redirects and 26 automatic-follow scenarios. Source hashes match across hosts;
all 346 native-host kernel/stdlib/ntest files and each compiler match the pinned
SDK manifests. Intel execution uses no Rosetta. Linux uses Ubuntu 24.04.5/glibc
2.39 inside the existing runner container. These are local development receipts;
independent package delivery/publication and mobile acceptance remain open.

## Portable source dependencies

Repository: <https://github.com/nylang/http_tls>. The source manifest uses implicit
SDK stdlib and public HTTPS Git dependencies pinned to exact commits. A private
NyraLang checkout and sibling dependency directory names are not required.
Native networking adapters and, for HTTPS, the pinned TLS/OpenSSL libraries
still require the documented platform build/link setup. Fetching Nyra package
sources does not build or link those native libraries.

```yaml
dependencies:
  http_tls:
    git: https://github.com/nylang/http_tls.git
    rev: main
```

Native `nyra` 1.0.3 or later handles explicit dependency acquisition. Use
`nyra lock ./app` to pin the initial branch selector, commit `nyra.lock`, then
`nyra fetch ./app --frozen` for repeatable preparation. Normal compilation and
analysis never fetch. The native manager's public SDK delivery is separate;
published SDK 1.0.2 does not include it. SDK 1.0.3 v2 locked SDK-runtime loading
requires the `buglist.sdk_portable_lock` compiler follow-up; the unchanged
accepted bootstrap does not include that follow-up.

For local development, map these package names to editable entries in a common
`workspace.yaml`. Keep public Git declarations in package manifests; workspace
registration alone does not add dependency edges. Source publication does not
create a tagged release or extend historical platform acceptance.
