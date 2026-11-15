// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Connects the configured TLS server handshake to HTTP/1.1 exchange admission. */
module SecureHttpServerAdapter;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "tls:tls.ny";
import "http_server:http_server.ny";
import "http:http2.ny";
import "http_server:http2_server.ny";
import "interface/https_server.ni";
import "private/websocket_tls.ny";

pub static method(HttpServerExchange) ReadSecure(
  connection: ref mut TcpConnection, config: ref TlsServerConfig, limits: ref HttpServerLimits,
  options: ref NetOperationOptions, persistent: bool
) -> Result<HttpServerExchange, HttpsServerError> {
  if config.alpn.length != 0 && config.alpn != "http/1.1" {
    return HttpsServerError{http_error: HttpServerError{kind: HttpServerErrorKind.InvalidArgument}};
  }

  var identity = config;
  identity.alpn = "http/1.1";
  var opened = TlsStream.NewServer(connection, identity);
  if opened.IsErr() {
    return HttpsServerError{tls_error: opened.get_if<TlsStreamError>()};
  }

  var adapter = WebSocketTls{stream: move(opened.get_if<TlsStream>() as TlsStream)};
  let handshake = adapter.Drive(adapter.stream.HandshakeAsync(options));
  if handshake.IsErr() {
    return HttpsServerError{tls_error: handshake.get_if<TlsStreamError>()};
  }

  var exchange = HttpServerExchange.ReadTransport(move(adapter), limits, options, persistent, require_framed_response: true);
  if exchange.IsErr() {
    return HttpsServerError{http_error: exchange.get_if<HttpServerError>()};
  }

  return move(exchange.get_if<HttpServerExchange>() as HttpServerExchange);
}

pub static method(Http2Server) ServeSecure(
  connection: ref mut TcpConnection, config: ref TlsServerConfig, provider_file: ref string,
  handler: ref mut Http2ServerHandler, limits: ref Http2Limits, options: ref NetOperationOptions
) -> Result<Unit, Https2ServerError> {
  if (config.alpn.length != 0 && config.alpn != "h2") || !limits.IsValid() || provider_file.length == 0 {
    return Https2ServerError{http_error: Http2Error{kind: Http2ErrorKind.InvalidArgument}};
  }

  var identity = config;
  identity.alpn = "h2";
  var opened = TlsStream.NewServer(connection, identity);
  if opened.IsErr() {
    return Https2ServerError{tls_error: opened.get_if<TlsStreamError>()};
  }

  var adapter = WebSocketTls{stream: move(opened.get_if<TlsStream>() as TlsStream)};
  let handshake = adapter.Drive(adapter.stream.HandshakeAsync(options));
  if handshake.IsErr() {
    adapter.stream.Close();
    return Https2ServerError{tls_error: handshake.get_if<TlsStreamError>()};
  }
  let selected = adapter.stream.SelectedAlpn();
  if selected.IsErr() {
    adapter.stream.Close();
    return Https2ServerError{tls_error: selected.get_if<TlsStreamError>()};
  }
  if (selected.get_if<string>() as string) != "h2" {
    adapter.stream.Close();
    return Https2ServerError{http_error: Http2Error{kind: Http2ErrorKind.Negotiation}};
  }

  let served = Http2Server.ServeTransport(move(adapter), true, provider_file, handler, limits, options);
  if served.IsErr() {
    return Https2ServerError{http_error: served.get_if<Http2Error>()};
  }

  return UnitValue();
}
