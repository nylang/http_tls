# http_tls 0.1.0

First source release of the optional verified HTTPS and automatic redirect
adapter. It shares HTTP grammar/framing with http and cryptography with tls.
Immutable and streamed bodies, 100-continue, early-final handling, response-first
TLS progress, URL-derived identity, bounded DNS and original absolute controls
are supported. Body-preserving redirects require both unsafe-replay permission
and explicit identical producer rewind acknowledgement before next-hop I/O.
No transport failure is automatically retried. Cross-origin filtering and HTTPS
downgrade rejection remain enforced.

The manifest pins exact public commits of net_core, TLS 0.2.0 and http 0.1.0.
Released package.yaml files keep Git declarations unchanged, with no relative
sibling dependency requirement. Corrected Nyra 1.0.4 tools are required for
lock/fetch and locked Git compilation. SDK 1.0.4 is not yet published at
preparation time; this release does not publish it. Pinned public SDK 1.0.2 is
used for protocol qualification in private acceptance snapshots, separately
from real Git-consumer qualification with corrected source tools.

The tag pipeline requires four native desktop hosts to pass 96 core cases,
96 isolated replays and the complete 276 TCP/HTTPS/DNS/upload/redirect scenarios.
Source/provider/SDK identities and exact dependency commits are retained with
the release. OpenSSL 3.5.9 static libraries, TLS/net_core native adapters and
platform link inputs must be built separately; no native binaries are bundled.
Explicit PEM CA trust is required. System stores, server TLS, mobile runtime,
pooling/reuse and HTTP/2/3 are not advertised.

Historical Windows connection timeouts remain an unresolved investigation
limitation. The release does not claim that later passing matrices fixed them.
The Nagle-sensitive Linux partial-head test peer was corrected without changing
production code or the 40/160 ms protocol fixture budgets.
