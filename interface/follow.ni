/** @brief Optional automatic redirect client selecting TCP or verified TLS per URL. */
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "tls:tls.ny";
import "http:http.ny";
import "interface/http_tls.ni";
/** @brief Exactly one original HTTP/TCP or HTTPS failure with its hop and owned URL.
 * @note Nested errors retain their stage and committed per-hop plaintext counts. Redirect policy
 *       errors use http_error and the last response's counts. No aggregate delivery is claimed.
 */
pub struct HttpFollowError { http_error: HttpClientError?; https_error: HttpsClientError?; redirect_count: int32; url: HttpUrl; }
/** @brief Move-only single-caller automatic redirect cursor; no transport retries or connection reuse. */
pub struct HttpFollowClient;
/** @brief A cursor owns its connection and cannot be duplicated. */
pub method(HttpFollowClient) operator copy() -> HttpFollowClient = delete;
/** @brief Transfer the sole cursor and current transport. */
pub method(HttpFollowClient) operator move() -> HttpFollowClient;
/** @brief Abort-close without draining response bodies or waiting for TLS shutdown. */
pub method(HttpFollowClient) operator drop() -> void;
/** @brief Own a validated request, redirect policy, copied TLS strings and original controls without I/O.
 * @note Next explicitly borrows the caller's resolver; keep using the same bounded pool. Dial settings
 *       and absolute deadline/shared cancellation are retained for every hop. Empty config.peer_name
 *       derives identity from each URL; a fixed peer must match every HTTPS hop. Explicit CA trust is
 *       required on HTTPS. TCP-only applications can use http without importing this optional package.
 */
pub static method(HttpFollowClient) New(url: ref HttpUrl, config: ref TlsClientConfig, verb: ref string, fields: ref <HttpField>[], body: ref NetBuffer, limits: ref HttpClientLimits, policy: ref HttpRedirectPolicy, dial: ref HttpDialOptions, options: ref NetOperationOptions) -> Result<HttpFollowClient, HttpFollowError>;
/** @brief Open lazily and pull events, following accepted redirects before publishing their heads/bodies.
 * @note Informational events remain observable at the current Url/RedirectCount. Terminal heads/body
 *       chunks and trailers retain ordinary ownership. Close each old connection before opening the
 *       next; never drain a redirect body. HTTPS downgrade and unsafe replay remain policy errors.
 *       Failures stick and retire the connection. Completed Next calls return Complete without I/O
 *       or control refresh until explicit Close/Shutdown; no automatic transport retry is performed.
 */
pub method(HttpFollowClient) Next(resolver: ref mut AsyncResolver) -> Result<HttpClientEvent, HttpFollowError>;
/** @brief Current hop URL; a rejected redirect retains the originating response URL. */
pub method(HttpFollowClient) Url() -> HttpUrl;
/** @brief Committed redirect count, excluding the initial request and rejected decisions. */
pub method(HttpFollowClient) RedirectCount() -> int32;
/** @brief Terminal response trailer count; pending state returns InvalidState without retiring the cursor. */
pub method(HttpFollowClient) TrailerCount() -> Result<int32, HttpFollowError>;
/** @brief Retain one owned terminal response trailer, or a nonterminal/index error. */
pub method(HttpFollowClient) TrailerAt(index: int32) -> Result<HttpField, HttpFollowError>;
/** @brief After HTTP completion, close TCP or complete TLS close_notify under the original controls.
 * @note Pending responses return InvalidState; shutdown failures stick and retire the transport.
 */
pub method(HttpFollowClient) Shutdown() -> Result<Unit, HttpFollowError>;
/** @brief Abort-close once while preserving the first error and hop identity. */
pub method(HttpFollowClient) Close() -> void;

/** @brief Own a streamed request and lazily follow redirects with explicit producer replay acknowledgement.
 * @note Plan, limits and continue_wait_ms match URL streaming. No body is buffered for replay.
 *       Rewrites to empty GET continue without a producer. Preserved nonempty/chunked requests require
 *       both allow_unsafe_replay and Explicit replay permission, even if an early final sent no payload.
 *       After an accepted preserved-body redirect, close the old transport, update Url/RedirectCount,
 *       and emit NeedReplay repeatedly without DNS or connection I/O. Caller rewinds an identical
 *       payload/trailer producer and calls ReplayBody before Next may open the new hop.
 *       The original deadline/token includes rewind time. There is no automatic transport retry.
 */
pub static method(HttpFollowClient) NewStreaming(url: ref HttpUrl, config: ref TlsClientConfig, verb: ref string, fields: ref <HttpField>[], plan: ref HttpBodyPlan, limits: ref HttpClientLimits, policy: ref HttpRedirectPolicy, replay: HttpBodyReplayPolicy, dial: ref HttpDialOptions, options: ref NetOperationOptions, continue_wait_ms: int32) -> Result<HttpFollowClient, HttpFollowError>;
/** @brief Retain immutable current-hop metadata, including streamed plan and filtered fields.
 * @note No producer bytes are retained. Snapshot outlives cursor changes; explicit failure is preserved.
 */
pub method(HttpFollowClient) Request() -> Result<HttpRedirectRequest, HttpFollowError>;
/** @brief Acknowledge one pending NeedReplay after rewinding an identical producer; performs no I/O.
 * @note Before/after the pending state returns nonterminal InvalidState. Cancellation/expiry retires
 *       the cursor. Never call merely to retry a transport failure; such failures remain terminal.
 */
pub method(HttpFollowClient) ReplayBody() -> Result<Unit, HttpFollowError>;
/** @brief Active opened streamed producer state; pending replay/unopened/immutable returns InvalidState. */
pub method(HttpFollowClient) UploadState() -> Result<HttpUploadState, HttpFollowError>;
/** @brief Supply one bounded owner after NeedBody; pending replay rejects admission without I/O. */
pub method(HttpFollowClient) SupplyBody(buffer: ref NetBuffer) -> Result<Unit, HttpFollowError>;
/** @brief Finish the active streamed producer; terminal shortages/framing failures retire the cursor. */
pub method(HttpFollowClient) FinishBody(trailers: ref <HttpField>[]) -> Result<Unit, HttpFollowError>;
