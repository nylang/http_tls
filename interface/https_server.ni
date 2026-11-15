// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "tls:tls.ny";
import "http_server:http_server.ny";

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
