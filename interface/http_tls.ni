/** @brief Optional connected HTTPS adapter; import http_tls:http_tls.ny and link the TLS package's pinned native inputs. */
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "tls:tls.ny";
import "http:http.ny";
/** @brief Exactly one protocol or original TLS-stream error, retaining committed HTTP plaintext wire progress. */
pub struct HttpsClientError { protocol_error: HttpError?; tls_error: TlsStreamError?; stage: HttpClientStage; stats: HttpClientStats; }
/** @brief Move-only single-request verified HTTPS client using the same exchange as plain TCP. */
pub struct HttpsClient;
/** @brief Connected HTTPS owners cannot be duplicated. */
pub method(HttpsClient) operator copy() -> HttpsClient = delete;
/** @brief Transfer TCP/TLS and all exchange state. */
pub method(HttpsClient) operator move() -> HttpsClient;
/** @brief Abort-close any retained TCP/TLS; graceful shutdown remains explicit. */
pub method(HttpsClient) operator drop() -> void;
/** @brief Validate request, Host/peer identity, HTTP/1.1 ALPN and controls before adopting TCP on success.
 * @note Failures leave connection untouched. DNS names compare ASCII case-insensitively; IP literals
 *       compare by address. No trailing-dot/IDNA/URL policy is supplied. Explicit trust is mandatory.
 *       Empty/http/1.1 config ALPN offers http/1.1; reject other offers. Negotiated absence or http/1.1
 *       is accepted; any other selection fails before HTTP output. One copied absolute control budget
 *       covers handshake, writes, reads and explicit Shutdown; pass original dial options unchanged.
 */
pub static method(HttpsClient) New(connection: ref mut TcpConnection, config: ref TlsClientConfig, head: ref NetBuffer, body: ref NetBuffer, limits: ref HttpClientLimits, options: ref NetOperationOptions) -> Result<HttpsClient, HttpsClientError>;
/** @brief Drive TLS Futures/Poll on the caller thread and pull one shared HTTP response event.
 * @note No worker or concurrent method calls. TLS failures remain TLS failures, never EOF. Only
 *       authenticated close_notify may complete EOF-delimited responses. Partial accepted writes on
 *       failure are counted without claiming ciphertext delivery. Errors retire TCP/TLS. Completion
 *       is durable until Close/Shutdown; completed connections cannot carry another exchange.
 */
pub method(HttpsClient) Next() -> Result<HttpClientEvent, HttpsClientError>;
/** @brief Completed trailer count, pending state failure or original terminal error. */
pub method(HttpsClient) TrailerCount() -> Result<int32, HttpsClientError>;
/** @brief Retain an owned completed trailer independently of the client. */
pub method(HttpsClient) TrailerAt(index: int32) -> Result<HttpField, HttpsClientError>;
/** @brief After HTTP completion, perform bidirectional close_notify with the original control budget.
 * @note Retires the client on success/failure without undoing already returned HTTP events. Pending
 *       HTTP responses return InvalidState without changing the cursor. Drop/Close is an abort instead.
 */
pub method(HttpsClient) Shutdown() -> Result<Unit, HttpsClientError>;
/** @brief Abort TCP/TLS without waiting; preserve the first error and its progress. */
pub method(HttpsClient) Close() -> void;
/** @brief Validate a request and open an https URL using explicit bounded DNS and one original control budget.
 * @note Derive Host, target and certificate/SNI identity from URL. Config peer_name may be empty or
 *       match that host; explicit CA trust remains required. Only http/1.1 ALPN is supported. DNS
 *       workers remain caller-owned; the call drives a private notification loop without busy waiting.
 *       Invalid request/identity/ALPN fails before dialing. No redirects, proxy, downgrade or pooling.
 */
pub static method(HttpsClient) Open(url: ref HttpUrl, config: ref TlsClientConfig, verb: ref string, fields: ref <HttpField>[], body: ref NetBuffer, limits: ref HttpClientLimits, resolver: ref mut AsyncResolver, dial: ref HttpDialOptions, options: ref NetOperationOptions) -> Result<HttpsClient, HttpsClientError>;
/** @brief Open a redirect snapshot with its retained original controls and URL-derived peer identity.
 * @note Caller explicitly closes the previous client after an accepted Follow. Config peer_name may
 *       be empty or match this hop; no transport failure is automatically retried or redirected.
 */
pub static method(HttpsClient) OpenRequest(request: ref HttpRedirectRequest, config: ref TlsClientConfig, resolver: ref mut AsyncResolver, dial: ref HttpDialOptions) -> Result<HttpsClient, HttpsClientError>;
