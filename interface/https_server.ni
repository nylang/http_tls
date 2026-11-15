// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "tls:tls.ny";
import "http_server:http_server.ny";
import "http:http2.ny";
import "http_server:http2_server.ny";

/** @brief TLS setup, ALPN or HTTP intake failure while opening the exchange. */
pub struct HttpsServerError {
  tls_error: TlsStreamError?;
  http_error: HttpServerError?;
}

/** @brief Open HTTP/1.1 on an accepted TCP connection, with optional persistence.
 * @note The PEM configuration must offer either an empty ALPN value or http/1.1.
 * This entry selects http/1.1 when the client offers ALPN. Responses must
 * have explicit framing or be bodyless. After TLS takes ownership, any
 * failure closes the connection. */
pub static method(HttpServerExchange) ReadSecure(
  connection: ref mut TcpConnection, config: ref TlsServerConfig, limits: ref HttpServerLimits,
  options: ref NetOperationOptions, persistent: bool
) -> Result<HttpServerExchange, HttpsServerError>;

/** @brief TLS setup, ALPN or HTTP/2 connection failure. */
pub struct Https2ServerError {
  tls_error: TlsStreamError?;
  http_error: Http2Error?;
}

/** @brief Serve one TLS connection after selecting ALPN h2. */
pub static method(Http2Server) ServeSecure(
  connection: ref mut TcpConnection, config: ref TlsServerConfig, provider_file: ref string,
  handler: ref mut Http2ServerHandler, limits: ref Http2Limits, options: ref NetOperationOptions
) -> Result<Unit, Https2ServerError>;

/** @brief Stream HTTP/2 on one TLS connection after selecting ALPN h2.
 * @note Takes the handler and uses the streaming provider entry point. */
pub static method(Http2Server) ServeStreamingSecure(
  connection: ref mut TcpConnection, config: ref TlsServerConfig, provider_file: ref string,
  handler: Http2StreamHandler, limits: ref Http2Limits, options: ref NetOperationOptions
) -> Result<Unit, Https2ServerError>;

/** @brief Identifies TLS, HTTP/1.1 or HTTP/2 failure on a negotiated server connection. */
pub struct HttpsNegotiatedError {
  tls_error: TlsStreamError?;
  http_error: HttpServerError?;
  http2_error: Http2Error?;
}

/** @brief TLS listener-side HTTP protocol dispatch. */
pub struct HttpsServer;

/** @brief Handshake once and dispatch an accepted connection by ALPN.
 * @note Prefers h2, then http/1.1. Clients without ALPN use HTTP/1.1.
 * Clients offering only other protocols fail the handshake. Supply an empty
 * config.alpn and the streaming HTTP/2 provider path. The HTTP/2 handler is
 * consumed, and the supplied controls cover the entire connection. */
pub static method(HttpsServer) ServeNegotiated(
  connection: ref mut TcpConnection, config: ref TlsServerConfig, provider_file: ref string,
  http1: ref mut HttpServerHandler, http2: Http2StreamHandler, http1_limits: ref HttpServerLimits,
  http2_limits: ref Http2Limits, options: ref NetOperationOptions
) -> Result<Unit, HttpsNegotiatedError>;
