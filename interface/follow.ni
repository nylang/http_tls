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
