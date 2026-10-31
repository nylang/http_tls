# http_tls

Development API 0.2.0 requires a matching Nyra SDK 1.0.5 or newer.
Rebuild precompiled consumers against the matching interfaces and runtime.

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
    rev: ea81032ac8829997db64e6d4ac4138bbbe2ed485
```

Use native `nyra` from the matching SDK 1.0.5. Run `nyra lock ./app`, commit
`nyra.lock`, then use `nyra fetch ./app --frozen` for repeatable preparation.
The example selects an existing public development commit with this API.
Compilation and analysis consume prepared dependencies without fetching them.
SDK/package publication and historical older-SDK acceptance remain separate.

For local development, map these package names to editable entries in a common
`workspace.yaml`. Keep public Git declarations in package manifests; workspace
registration alone does not add dependency edges. Source publication does not
create a tagged release or extend historical platform acceptance.


## Local development: streamed connected HTTPS

`HttpsClient.NewStreaming(connection, config, head, limits, options, continue_wait_ms)`
adds a producer-driven connected HTTPS path over the optional `tls.TlsChannel`.
The existing immutable constructor, URL helpers and redirect clients retain their
behavior. Plain HTTP imports remain TLS-free; both connected facades share the
same exchange, parsers, limits, body writer and producer admission rules.

Validate head, peer identity, ALPN, trust configuration and a finite 0..60000 ms
continue fallback before adopting TCP. Zero TLS BIO capacity selects 65536;
explicit capacity must be at least 32768. Verified handshake and accepted ALPN
precede HTTP output. `Next` emits `NeedBody` to request one nonempty immutable
owner of at most 16 KiB including backing, or `FinishBody(trailers)`. Producer
time remains inside the original deadline/token, without callbacks or replay.

Buffered/available responses precede further body writes. The continue timer
starts once after complete head ciphertext flush; only 100 or finite fallback
releases the gate, while partial heads pause upload. TLS provider retry barriers
still take precedence: callers never switch operations during a reserved retry.
Write backpressure otherwise monitors read and write readiness so an early final
can be decrypted before more queued upload is sent. One iteration owns no
unreported asynchronous write; actual TLS-accepted plaintext is acknowledged
before response parsing. TCP delivery may lag that count.

Final responses stop an unfinished producer and revoke unsent plaintext. They do
not undo bytes already accepted by TLS. The channel may still hold ciphertext
for an accepted prefix, which abort-close discards without rewriting/replaying
records. After response completion, `Shutdown` abort-closes a Stopped upload
rather than flushing it merely to send close_notify. Finished requests use
bidirectional close_notify under original controls. Completion stays durable
until explicit Close/Shutdown, and retained heads/body owners outlive the client.
Authenticated EOF may end a close-delimited HTTP response; raw TLS truncation
remains a TLS error. An authenticated close before a fixed HTTP body completes
remains an HTTP UnexpectedEof instead. No error triggers transport retry,
producer replay or automatic redirects.


The [source acceptance](../http/docs/https-upload-acceptance-2026-10-28.json)
passes on macOS arm64, Linux x86_64 and Windows x86_64 with matching SDK 1.0.2:
88 core/replay cases, 181 network/control scenarios, 39 TLS/replay cases and 73
native TLS cases per host. New HTTPS scenarios check constructor rollback,
producer admission/moves, fixed/chunked/trailer wire, 103/100 and finite fallback,
early rejection under constrained receive-window pressure, deadline/cancellation
continuity, authenticated versus raw truncation, untrusted CA before HTTP and
graceful versus abort shutdown. Intel macOS remains pending authorized SSH recovery.
The Windows receipt retains an unconfirmed prior TCP redirect-open failure and
successful unchanged isolated/full retries; that fault investigation stays open.
That connected-only snapshot predates the URL streaming helpers below. Explicit
producer replay and automatic redirect integration were added later, as described
below. No new tagged release is implied.

## Local development: URL streaming

`HttpsClient.OpenStreaming(url, config, verb, fields, plan, limits, resolver,
dial, options, continue_wait_ms)` opens a streamed request from a strict HTTPS
URL. It uses `HttpUrl.StreamingRequestHead` and the existing optional TLS channel.
The URL supplies Host, escaped origin target and certificate/SNI identity. An
empty config peer name is filled from the URL; a conflicting name or unsupported
ALPN is rejected before DNS. Request framing, limits and finite continue policy
are also checked before DNS. CA/provider/channel resources are checked after
dial and before HTTP output; explicit trust remains mandatory.

The resolver is borrowed only during open; numeric IP URLs bypass it. Next may
return NeedBody, followed by SupplyBody or FinishBody using bounded owned blocks.
Resolution, dialing, handshake, continue waiting and producer time consume the
same original deadline/token. There is no automatic producer replay or redirect.
Immutable Open/OpenRequest retain their previous behavior. This is unreleased
local development.

[URL acceptance](../http/docs/url-upload-acceptance-2026-10-28.json) records
91 core cases/replays and 231 network/control scenarios on each of macOS arm64,
Linux x86_64 and Windows x86_64 with pinned public SDK 1.0.2. Native Intel remains
pending SSH restoration. Prior unexplained Windows connection timeouts remain
open; this candidate passed the complete suite without relaxing test budgets.

## Local development: streamed automatic redirects

`HttpFollowClient.NewStreaming` combines URL streaming with the shared redirect
chain. Its signature adds an upload plan, `HttpBodyReplayPolicy` and finite
continue wait to the ordinary follow constructor. The initial request is opened
lazily by `Next(resolver)`; producer blocks are still bounded and caller-owned.
The resolver is explicitly borrowed for each hop. TLS strings, dial options,
limits and the original absolute deadline/shared cancellation are retained.

Drive the cursor as follows:

1. On `NeedBody`, call `SupplyBody` with the next immutable block, or `FinishBody`
   with final trailers once all payload has drained.
2. A body-preserving redirect requires both `allow_unsafe_replay` and `Explicit`
   replay policy. The cursor closes the old connection without draining its
   response or flushing additional upload data, commits the new URL/hop, then
   returns `NeedReplay` with zero new-hop progress.
3. Inspect `Request()` if needed, reset the producer to the beginning of the
   identical payload/trailers, and call `ReplayBody()`. Only a later `Next` may
   resolve/connect the target. Repeated `Next` calls before acknowledgement
   return `NeedReplay` with no DNS or connection work. Body admission while
   pending replay is nonterminal `InvalidState`; duplicate acknowledgement is
   likewise rejected without changing the cursor.
4. Read terminal heads/body/trailers normally. Followed redirect heads/bodies
   remain suppressed; informational events remain visible. Empty GET rewrites
   proceed directly without a replay acknowledgement or a new body producer.

`Never` rejects preserved producer replay even if no payload was sent. A caller
without a repeatable source can still follow a rewrite that drops the body.
The library does not retain or verify replay payloads: `Explicit` plus
`ReplayBody` is the caller's attestation, not a transparent rewind callback.
Producer rewind time consumes the same original control budget; cancellation or
expiry while paused closes the cursor and preserves target URL/hop identity.
There is no automatic transport retry, pooling or HTTPS downgrade. Shared field
filtering remains in force; cross-origin and Connection-nominated streamed
Trailer promises are rejected rather than silently dropped. Immutable New and
its existing event behavior remain unchanged.

[Streamed follow acceptance](../http/docs/stream-follow-acceptance-2026-10-28.json)
records matching public SDK 1.0.2 on macOS arm64, Linux x86_64 and Windows x86_64:
96 core cases/replays and 276 network/control scenarios per host. Native Intel
remains pending SSH restoration. The first Linux partial-head fixture failure,
48 old/new binary comparisons and final complete matrix are recorded separately
from historical Windows connection timeout investigations. No new package is released.


## Published 0.1.1

[http_tls 0.1.1](https://github.com/nylang/http_tls/releases/tag/v0.1.1) is the
first published adapter source release, pinning the exact HTTP 0.1.1 and TLS
0.2.0 commits through public Git dependencies. The four native desktop jobs
and publisher passed: 96 core cases/replays and 276 network/control scenarios
per host. See [publication](docs/publication-0.1.1.json) and
[real locked Git consumption](docs/git-consumer-0.1.1.json).

Published package.yaml files and source archives preserve the original Git
edges without relative dependency rewrites. Corrected source Nyra 1.0.4 tools
pass online lock/fetch, moved offline resolution, checking, linking and execution;
SDK 1.0.4 publication remains separate. Native providers/adapters still require
explicit builds. The earlier two Windows 0.1.0 fixture failures and failed or
skipped publishing attempts remain historical evidence. The IPv4-only deadline
fixture now selects IPv4 for cases 12/13; deadlines and production behavior are
unchanged. Other default-family URL cases remain in the accepted matrix.
Historical general Windows connection-fault investigations remain open.

## Module architecture

See [module responsibilities, ownership and dependency boundaries](ARCHITECTURE.md).

## Coding-rule lint

`package.yaml` selects the portable `lint.yaml` profile. It requires the
1.0.5 P7 analyzer candidate (or a later SDK containing those rules); the
published 1.0.4 analyzer does not implement them. `import: default` inherits
the selected workspace profile when present, otherwise analyzer SDK defaults.
No sibling source path is required. Run `nyra-analyzer lint . --json`. Lint checks
coding rules; runtime qualification is a separate gate.
