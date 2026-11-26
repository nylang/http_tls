// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "tls:tls.ny";
import "http:http.ny";

/** @brief Failure while resolving, verifying TLS or opening a secure WebSocket. */
pub struct SecureWebSocketError {
  websocket_error: WebSocketError?;
  tls_error: TlsStreamError?;
}

/** @brief Open a verified wss:// connection using the URL's DNS name or IP as peer identity.
 * @param ca_file Required PEM trust file for the existing TLS client.
 * @note The same controls apply to DNS, TCP, TLS and HTTP upgrade. The resulting WebSocket
 * accepts independent controls per operation. Only HTTP/1.1 or absent ALPN is accepted.
 * @returns An owned session or a URL, network, TLS or opening-handshake error.
 */
pub static method(WebSocket) OpenSecure(
  url: ref string, ca_file: ref string, resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions, limits: ref WebSocketLimits, options: ref NetOperationOptions
) -> Result<WebSocket, SecureWebSocketError>;
