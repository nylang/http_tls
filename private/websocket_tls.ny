// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Drives verified TLS over a WebSocket's ordered byte transport. */
module SecureWebSocketAdapter;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "tls:tls.ny";
import "http:http.ny";
import "interface/websocket_tls.ni";

struct WebSocketTls implements WebSocketTransport {
  stream: TlsStream;
}

method(WebSocketTls) Drive(
  queued: Result<AsyncFuture<TlsTransfer>, TlsStreamError>
) -> Result<TlsTransfer, TlsStreamError> {
  if queued.IsErr() {
    return queued.get_if<TlsStreamError>() as TlsStreamError;
  }

  let future = queued.get_if<AsyncFuture<TlsTransfer>>() as AsyncFuture<TlsTransfer>;
  while !future.is_completed {
    let polled = self.stream.Poll(-1);
    if polled.IsErr() {
      return polled.get_if<TlsStreamError>() as TlsStreamError;
    }
  }

  let done = future.GetResult();
  if done.IsErr() {
    return TlsStreamError{tls_error: TlsError{kind: TlsErrorKind.InvalidState}};
  }

  let transfer = done.get_if<TlsTransfer>() as TlsTransfer;
  if transfer.error != nil {
    return transfer.error as TlsStreamError;
  }

  return transfer;
}

static method(WebSocketTls) OperationError(error: ref TlsStreamError) -> WebSocketError {
  if error.transport_error != nil {
    return WebSocketError{kind: WebSocketErrorKind.Transport, network_error: error.transport_error};
  }

  return WebSocketError{kind: WebSocketErrorKind.Tls};
}

@override
method(WebSocketTls) Read(buffer: ref NetMutableBytes, options: ref NetOperationOptions) -> Result<intptr, WebSocketError> {
  let result = self.Drive(self.stream.ReadAsync(buffer.Len() as int32, options));
  if result.IsErr() {
    return WebSocketTls.OperationError(result.get_if<TlsStreamError>() as TlsStreamError);
  }

  let transfer = result.get_if<TlsTransfer>() as TlsTransfer;
  let bytes = transfer.buffer.Bytes();
  if bytes.Len() > 0ip {
    unsafe {
      memcpy(buffer.Data(), bytes.Data(), bytes.Len() as uintptr);
    }
  }

  return bytes.Len();
}

@override
method(WebSocketTls) WriteAll(buffer: ref NetBytes, options: ref NetOperationOptions) -> Result<Unit, WebSocketError> {
  var offset: intptr = 0;
  while offset < buffer.Len() {
    let remaining = buffer.Len() - offset;
    let size = remaining < 16384ip ? remaining : 16384ip;
    let bytes = buffer.Slice(offset, size).get_if<NetBytes>() as NetBytes;
    let copied = NetBuffer.CopyFrom(bytes);
    if copied.IsErr() {
      return WebSocketError{kind: WebSocketErrorKind.ResourceExhausted, network_error: copied.get_if<NetError>()};
    }

    let block = copied.get_if<NetBuffer>() as NetBuffer;
    let result = self.Drive(self.stream.WriteAllAsync(block, options));
    if result.IsErr() {
      return WebSocketTls.OperationError(result.get_if<TlsStreamError>() as TlsStreamError);
    }
    offset += size;
  }

  return UnitValue();
}

@override
method(WebSocketTls) Abort() -> void {
  self.stream.Close();
}

pub static method(WebSocket) OpenSecure(
  url: ref string, ca_file: ref string, resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions, limits: ref WebSocketLimits, options: ref NetOperationOptions
) -> Result<WebSocket, SecureWebSocketError> {
  let parsed = WebSocket.ParseUrl(url);
  if parsed.IsErr() {
    return SecureWebSocketError{websocket_error: parsed.get_if<WebSocketError>()};
  }

  let route = parsed.get_if<HttpUrl>() as HttpUrl;
  if !route.IsSecure() || ca_file.length == 0 || !limits.IsValid() {
    return SecureWebSocketError{websocket_error: WebSocketError{kind: WebSocketErrorKind.InvalidArgument}};
  }

  var dialed = route.Dial(resolver, dial, options);
  if dialed.IsErr() {
    let error = dialed.get_if<HttpClientError>() as HttpClientError;
    return SecureWebSocketError{websocket_error: WebSocketError{kind: WebSocketErrorKind.Transport,
      network_error: error.transport_error, http_error: error.protocol_error}};
  }

  var connection = move(dialed.get_if<TcpConnection>() as TcpConnection);
  let config = TlsClientConfig{peer_name: route.Host(), ca_file: ca_file, alpn: "http/1.1"};
  var stream = TlsStream.NewClient(connection, config);
  if stream.IsErr() {
    return SecureWebSocketError{tls_error: stream.get_if<TlsStreamError>()};
  }

  var adapter = WebSocketTls{stream: move(stream.get_if<TlsStream>() as TlsStream)};
  let handshake = adapter.Drive(adapter.stream.HandshakeAsync(options));
  if handshake.IsErr() {
    return SecureWebSocketError{tls_error: handshake.get_if<TlsStreamError>()};
  }

  let selected = adapter.stream.SelectedAlpn();
  if selected.IsErr() {
    return SecureWebSocketError{tls_error: selected.get_if<TlsStreamError>()};
  }

  let alpn = selected.get_if<string>() as string;
  if alpn.length != 0 && alpn != "http/1.1" {
    return SecureWebSocketError{websocket_error: WebSocketError{kind: WebSocketErrorKind.Handshake}};
  }

  var opened = WebSocket.Connect(move(adapter), route, limits, options);
  if opened.IsErr() {
    return SecureWebSocketError{websocket_error: opened.get_if<WebSocketError>()};
  }

  return move(opened.get_if<WebSocket>() as WebSocket);
}
