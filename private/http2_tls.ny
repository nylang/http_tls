// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Adapts a verified TLS stream to the HTTP/2 byte transport. */
module SecureHttp2Adapter;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "tls:tls.ny";
import "http:http.ny";
import "http:http2.ny";
import "interface/http2_tls.ni";

struct Http2Tls implements Http2Transport {
  stream: TlsStream;
}

method(Http2Tls) Drive(
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

static method(Http2Tls) OperationError(error: ref TlsStreamError) -> Http2Error {
  if error.transport_error != nil {
    return Http2Error{kind: Http2ErrorKind.Network, network: error.transport_error};
  }

  return Http2Error{kind: Http2ErrorKind.Tls};
}

@override
method(Http2Tls) Read(buffer: ref NetMutableBytes, options: ref NetOperationOptions) -> Result<intptr, Http2Error> {
  let result = self.Drive(self.stream.ReadAsync(buffer.Len() as int32, options));
  if result.IsErr() {
    return Http2Tls.OperationError(result.get_if<TlsStreamError>() as TlsStreamError);
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
method(Http2Tls) WriteAll(buffer: ref NetBytes, options: ref NetOperationOptions) -> Result<Unit, Http2Error> {
  var offset: intptr = 0;
  while offset < buffer.Len() {
    let remaining = buffer.Len() - offset;
    let size = remaining < 16384ip ? remaining : 16384ip;
    let bytes = buffer.Slice(offset, size).get_if<NetBytes>() as NetBytes;
    let copied = NetBuffer.CopyFrom(bytes);
    if copied.IsErr() {
      return Http2Error{kind: Http2ErrorKind.ResourceExhausted, network: copied.get_if<NetError>()};
    }

    let block = copied.get_if<NetBuffer>() as NetBuffer;
    let result = self.Drive(self.stream.WriteAllAsync(block, options));
    if result.IsErr() {
      return Http2Tls.OperationError(result.get_if<TlsStreamError>() as TlsStreamError);
    }
    offset += size;
  }

  return UnitValue();
}

@override
method(Http2Tls) Abort() -> void {
  self.stream.Close();
}

pub static method(Http2Client) OpenSecure(
  url: ref HttpUrl, ca_file: ref string, provider_file: ref string, resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions, limits: ref Http2Limits, options: ref NetOperationOptions
) -> Result<Http2Client, SecureHttp2Error> {
  if !url.IsValid() || !url.IsSecure() || ca_file.length == 0 || provider_file.length == 0 || !limits.IsValid() {
    return SecureHttp2Error{protocol: Http2Error{kind: Http2ErrorKind.InvalidArgument}};
  }

  var dialed = url.Dial(resolver, dial, options);
  if dialed.IsErr() {
    let error = dialed.get_if<HttpClientError>() as HttpClientError;
    return SecureHttp2Error{protocol: Http2Error{kind: Http2ErrorKind.Network, network: error.transport_error}};
  }

  var connection = move(dialed.get_if<TcpConnection>() as TcpConnection);
  let delay = connection.SetNoDelay(true);
  if delay.IsErr() {
    return SecureHttp2Error{protocol: Http2Error{kind: Http2ErrorKind.Network, network: delay.get_if<NetError>()}};
  }

  let config = TlsClientConfig{peer_name: url.Host(), ca_file: ca_file, alpn: "h2"};
  var stream = TlsStream.NewClient(connection, config);
  if stream.IsErr() {
    return SecureHttp2Error{tls: stream.get_if<TlsStreamError>()};
  }

  var adapter = Http2Tls{stream: move(stream.get_if<TlsStream>() as TlsStream)};
  let handshake = adapter.Drive(adapter.stream.HandshakeAsync(options));
  if handshake.IsErr() {
    return SecureHttp2Error{tls: handshake.get_if<TlsStreamError>()};
  }

  let selected = adapter.stream.SelectedAlpn();
  if selected.IsErr() {
    return SecureHttp2Error{tls: selected.get_if<TlsStreamError>()};
  }
  if (selected.get_if<string>() as string) != "h2" {
    return SecureHttp2Error{protocol: Http2Error{kind: Http2ErrorKind.Negotiation}};
  }

  var opened = Http2Client.Adopt(move(adapter), url, provider_file, limits);
  if opened.IsErr() {
    return SecureHttp2Error{protocol: opened.get_if<Http2Error>()};
  }

  return move(opened.get_if<Http2Client>() as Http2Client);
}
