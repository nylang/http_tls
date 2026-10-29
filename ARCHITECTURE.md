# http_tls module architecture

This package already has two independent ownership boundaries; keeping those
boundaries is intentional, rather than increasing module count to meet a quota.

- `private/http_tls.ny` with `upload.ny` owns one connected HTTPS hop. Both parts
  mutate the same TLS adapter/exchange progress, original controls and retry state.
  It consumes the shared HTTP exchange and TLS stream/channel operations; it does
  not implement HTTP grammar, DNS selection or redirect-chain policy.
- `private/follow.ny` owns the automatic multi-hop cursor, original request policy,
  explicit producer replay acknowledgement and current-hop lifetime. Its dependency
  on the connected adapter is explicit. It also consumes HTTP redirect and dial
  operations; it cannot access the adapter's private `HttpsData` layout.

A hop's terminal failure is retained by its adapter. The cursor retires the old
hop before opening another and preserves the original deadline/token across DNS,
TLS, body producer time and replay. The connected adapter never calls the cursor.
Buffered and streamed scheduling stay parts of one adapter owner, rather than
becoming two modules sharing a public mutable state record. Existing HTTP/HTTPS
consumer acceptance scenarios exercise both boundaries.
