// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Optional TLS adapter for the shared HTTP exchange; no duplicate HTTP grammar. */
module HttpsClientAdapter;
part "upload.ny";
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "tls:tls.ny";
import "http:http.ny";
import "interface/http_tls.ni";

struct HttpsData {
  stream: TlsStream;
  channel: TlsChannel;
  streaming: bool;
  head_flushed: bool;
  continue_started: bool;
  continue_wait_ms: int32;
  continue_deadline: NetDeadline;
  exchange: HttpClientExchange;
  options: NetOperationOptions;
  handshaken: bool;
  published_complete: bool;
  failure: HttpsClientError?;
}

/** @brief Move-only single-request verified HTTPS client using the same exchange as plain TCP. */
pub struct HttpsClient {
  cell: arc<HttpsData>?;
}

func https_protocol(s: arc<HttpsData>, error: HttpError) -> HttpsClientError {
  return HttpsClientError{protocol_error: error, stage: s.exchange.Stage(), stats: s.exchange.Stats()};
}

func https_provider(s: arc<HttpsData>, error: TlsStreamError) -> HttpsClientError {
  return HttpsClientError{tls_error: error, stage: s.exchange.Stage(), stats: s.exchange.Stats()};
}

func https_control(error: NetError) -> TlsStreamError {
  return TlsStreamError{transport_error: error};
}

func https_fail(state: arc<HttpsData>, error: HttpsClientError) -> HttpsClientError {
  var s: arc<HttpsData> = state;
  s.stream.Close();
  s.channel.Close();
  s.exchange = HttpClientExchange{};
  s.failure = error;

  return error;
}

// Compare parsed IP addresses by value, but fold only ASCII case for DNS peer names.
func https_identity(host: ref string, peer: ref string) -> bool {
  let a: Result<IpAddress, NetError> = IpAddress.Parse(host);
  let b: Result<IpAddress, NetError> = IpAddress.Parse(peer);
  if a.IsOk() || b.IsOk() {
    return a.IsOk()
      && b.IsOk()
      && ((a.get_if<IpAddress>()) as IpAddress).Equals((b.get_if<IpAddress>()) as IpAddress);
  }

  if host.length != peer.length {
    return false;
  }

  var i: int32 = 0;
  while i < host.length {
    var x: int32 = (host[i] as uint8) as int32;
    var y: int32 = (peer[i] as uint8) as int32;
    if x >= 65 && x <= 90 {
      x = x + 32;
    }

    if y >= 65 && y <= 90 {
      y = y + 32;
    }

    if x != y {
      return false;
    }

    i = i + 1;
  }

  return true;
}

func https_wait(
  stream: ref mut TlsStream,
  queued: Result<AsyncFuture<TlsTransfer>, TlsStreamError>
) -> Result<TlsTransfer, TlsStreamError> {
  if queued.IsErr() {
    return (queued.get_if<TlsStreamError>()) as TlsStreamError;
  }

  let future: AsyncFuture<TlsTransfer> = (
    queued.get_if<AsyncFuture<TlsTransfer>>()
  ) as AsyncFuture<TlsTransfer>;
  while !future.is_completed {
    let polled: Result<int32, TlsStreamError> = stream.Poll(-1);
    if polled.IsErr() {
      return (polled.get_if<TlsStreamError>()) as TlsStreamError;
    }
  }

  let result: Result<TlsTransfer, AsyncError> = future.GetResult();
  if result.IsErr() {
    return TlsStreamError{tls_error: TlsError{kind: TlsErrorKind.InvalidState}};
  }

  return (result.get_if<TlsTransfer>()) as TlsTransfer;
}

/**
 * @brief Validate request, Host/peer identity, HTTP/1.1 ALPN and controls before adopting TCP on
 *   success.
 * @returns Ok with HttpsClient on success; Err with HttpsClientError on the failure paths
 *   described above.
 * @note Failures leave connection untouched. DNS names compare ASCII case-insensitively; IP
 *   literals compare by address. No trailing-dot/IDNA/URL policy is supplied. Explicit trust is
 *   mandatory. Empty/http/1.1 config ALPN offers http/1.1; reject other offers. Negotiated absence
 *   or http/1.1 is accepted; any other selection fails before HTTP output. One copied absolute
 *   control budget covers handshake, writes, reads and explicit Shutdown; pass original dial
 *   options unchanged.
 */
pub static method(HttpsClient) New(
  connection: ref mut TcpConnection,
  config: ref TlsClientConfig,
  head: ref NetBuffer,
  body: ref NetBuffer,
  limits: ref HttpClientLimits,
  options: ref NetOperationOptions
) -> Result<HttpsClient, HttpsClientError> {
  let control: Result<Unit, NetError> = options.Check(NetClock.NowNanoseconds());
  if control.IsErr() {
    return HttpsClientError{tls_error: https_control((control.get_if<NetError>()) as NetError)};
  }

  var core: Result<HttpClientExchange, HttpError> = HttpClientExchange.New(head, body, limits);
  if core.IsErr() {
    return HttpsClientError{protocol_error:(core.get_if<HttpError>()) as HttpError};
  }

  var exchange: HttpClientExchange = move((core.get_if<HttpClientExchange>()) as HttpClientExchange);
  let host: string = (exchange.AuthorityHost().get_if<string>()) as string;
  if !https_identity(host, config.peer_name) {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}};
  }

  if config.alpn.length != 0 && !config.alpn.Equal("http/1.1") {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.Unsupported}};
  }

  var settings: TlsClientConfig = config;
  settings.alpn = "http/1.1";
  var stream: Result<TlsStream, TlsStreamError> = TlsStream.NewClient(connection, settings);
  if stream.IsErr() {
    return HttpsClientError{tls_error:(stream.get_if<TlsStreamError>()) as TlsStreamError};
  }

  return HttpsClient{cell: new arc<HttpsData>{
    stream: move((stream.get_if<TlsStream>()) as TlsStream),
    exchange: move(exchange),
    options: options
  }};
}

/**
 * @brief Transfer TCP/TLS and all exchange state.
 * @returns The HttpsClient value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpsClient) operator move() -> HttpsClient {
  let cell: arc<HttpsData>? = self.cell;
  self.cell = nil;

  return HttpsClient{cell: cell};
}

/** @brief Abort-close retained resources on drop. */
pub method(HttpsClient) operator drop() -> void {
  self.Close();
  self.cell = nil;
}

/**
 * @brief Drive TLS Futures/Poll on the caller thread and pull one shared HTTP response event.
 * @returns Ok with HttpClientEvent on success; Err with HttpsClientError on the failure paths
 *   described above.
 * @note Streamed clients may emit NeedBody; drain events and supply one body owner or finish.
 *   Reads precede further body writes; provider retry barriers still take priority. No worker or
 *   concurrent method calls. TLS failures remain TLS failures, never EOF. Only authenticated
 *   close_notify may complete EOF-delimited responses. Partial accepted writes on failure are
 *   counted without claiming ciphertext delivery. Errors retire TCP/TLS. Completion is durable
 *   until Close/Shutdown; completed connections cannot carry another exchange.
 */
pub method(HttpsClient) Next() -> Result<HttpClientEvent, HttpsClientError> {
  if self.cell == nil {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.Closed}};
  }

  var s: arc<HttpsData> = self.cell as arc<HttpsData>;
  if s.failure != nil {
    return s.failure as HttpsClientError;
  }

  if s.published_complete {
    return HttpClientEvent{kind: HttpClientEventKind.Complete, complete: true, stats: s.exchange.Stats()};
  }

  if s.streaming {
    return https_stream_next(s);
  }

  while true {
    let control: Result<Unit, NetError> = s.options.Check(NetClock.NowNanoseconds());
    if control.IsErr() {
      return https_fail(s, https_provider(s, https_control((control.get_if<NetError>()) as NetError)));
    }

    if !s.handshaken {
      let result: Result<TlsTransfer, TlsStreamError> = https_wait(
        s.stream,
        s.stream.HandshakeAsync(s.options)
      );
      if result.IsErr() {
        return https_fail(s, https_provider(s,(result.get_if<TlsStreamError>()) as TlsStreamError));
      }

      let transfer: TlsTransfer = (result.get_if<TlsTransfer>()) as TlsTransfer;
      if transfer.error != nil {
        return https_fail(s, https_provider(s, transfer.error as TlsStreamError));
      }

      let selected: Result<string, TlsStreamError> = s.stream.SelectedAlpn();
      if selected.IsErr() {
        return https_fail(s, https_provider(s,(selected.get_if<TlsStreamError>()) as TlsStreamError));
      }

      let protocol: string = (selected.get_if<string>()) as string;
      if protocol.length != 0 && !protocol.Equal("http/1.1") {
        return https_fail(s, https_protocol(s, HttpError{kind: HttpErrorKind.Unsupported}));
      }

      s.handshaken = true;
      continue;
    }

    if !s.exchange.RequestComplete() {
      let output: Result<NetBuffer, HttpError> = s.exchange.Output();
      if output.IsErr() {
        return https_fail(s, https_protocol(s,(output.get_if<HttpError>()) as HttpError));
      }

      let block: NetBuffer = (output.get_if<NetBuffer>()) as NetBuffer;
      if block.Len() == (0 as intptr) {
        if s.exchange.RequestComplete() {
          continue;
        }

        return https_fail(s, https_protocol(s, HttpError{kind: HttpErrorKind.InvalidState}));
      }

      let result: Result<TlsTransfer, TlsStreamError> = https_wait(
        s.stream,
        s.stream.WriteAllAsync(block, s.options)
      );
      if result.IsErr() {
        return https_fail(s, https_provider(s,(result.get_if<TlsStreamError>()) as TlsStreamError));
      }

      let transfer: TlsTransfer = (result.get_if<TlsTransfer>()) as TlsTransfer;
      let acknowledged: Result<Unit, HttpError> = s.exchange.AcknowledgeOutput(transfer.bytes_transferred);
      if acknowledged.IsErr() {
        return https_fail(s, https_protocol(s,(acknowledged.get_if<HttpError>()) as HttpError));
      }

      if transfer.error != nil {
        return https_fail(s, https_provider(s, transfer.error as TlsStreamError));
      }

      if transfer.bytes_transferred != block.Len() {
        return https_fail(s, https_protocol(s, HttpError{kind: HttpErrorKind.InvalidState}));
      }

      continue;
    }

    let advanced: Result<HttpClientEvent, HttpError> = s.exchange.NextResponse();
    if advanced.IsErr() {
      return https_fail(s, https_protocol(s,(advanced.get_if<HttpError>()) as HttpError));
    }

    let event: HttpClientEvent = (advanced.get_if<HttpClientEvent>()) as HttpClientEvent;
    if event.kind != HttpClientEventKind.NeedInput {
      let final_control: Result<Unit, NetError> = s.options.Check(NetClock.NowNanoseconds());
      if final_control.IsErr() {
        return https_fail(
          s,
          https_provider(s, https_control((final_control.get_if<NetError>()) as NetError))
        );
      }

      s.published_complete = event.complete;

      return event;
    }

    let result: Result<TlsTransfer, TlsStreamError> = https_wait(
      s.stream,
      s.stream.ReadAsync(16384, s.options)
    );
    if result.IsErr() {
      return https_fail(s, https_provider(s,(result.get_if<TlsStreamError>()) as TlsStreamError));
    }

    let transfer: TlsTransfer = (result.get_if<TlsTransfer>()) as TlsTransfer;
    if transfer.error != nil {
      var error: HttpsClientError = https_provider(s, transfer.error as TlsStreamError);
      error.stats.response_bytes_received = error.stats.response_bytes_received + (
        transfer.bytes_transferred as uint64
      );

      return https_fail(s, error);
    }

    if transfer.bytes_transferred != transfer.buffer.Len()
      || (transfer.bytes_transferred == (0 as intptr) && !transfer.eof) {
      return https_fail(s, https_protocol(s, HttpError{kind: HttpErrorKind.InvalidState}));
    }

    let received: Result<Unit, HttpError> = s.exchange.Receive(transfer.buffer, transfer.eof);
    if received.IsErr() {
      return https_fail(s, https_protocol(s,(received.get_if<HttpError>()) as HttpError));
    }
  }
}

/**
 * @brief Completed trailer count, pending state failure or original terminal error.
 * @returns Ok with int32 on success; Err with HttpsClientError on the failure paths described
 *   above.
 */
pub method(HttpsClient) TrailerCount() -> Result<int32, HttpsClientError> {
  if self.cell == nil {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.Closed}};
  }

  let s: arc<HttpsData> = self.cell as arc<HttpsData>;
  if s.failure != nil {
    return s.failure as HttpsClientError;
  }

  let result: Result<int32, HttpError> = s.exchange.TrailerCount();
  if result.IsErr() {
    return https_protocol(s,(result.get_if<HttpError>()) as HttpError);
  }

  return (result.get_if<int32>()) as int32;
}

/**
 * @brief Retain an owned completed trailer independently of the client.
 * @returns Ok with HttpField on success; Err with HttpsClientError on the failure paths
 *   described above.
 */
pub method(HttpsClient) TrailerAt(index: int32) -> Result<HttpField, HttpsClientError> {
  if self.cell == nil {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.Closed}};
  }

  let s: arc<HttpsData> = self.cell as arc<HttpsData>;
  if s.failure != nil {
    return s.failure as HttpsClientError;
  }

  let result: Result<HttpField, HttpError> = s.exchange.TrailerAt(index);
  if result.IsErr() {
    return https_protocol(s,(result.get_if<HttpError>()) as HttpError);
  }

  return (result.get_if<HttpField>()) as HttpField;
}

/**
 * @brief After HTTP completion, perform bidirectional close_notify with the original control
 *   budget.
 * @returns Ok with Unit on success; Err with HttpsClientError on the failure paths described
 *   above.
 * @note Retires the client on success/failure without undoing already returned HTTP events.
 *   Pending HTTP responses return InvalidState without changing the cursor. Drop/Close is an abort
 *   instead. Streamed uploads stopped by a final response are abort-closed without flushing
 *   remaining upload.
 */
pub method(HttpsClient) Shutdown() -> Result<Unit, HttpsClientError> {
  if self.cell == nil {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.Closed}};
  }

  let s: arc<HttpsData> = self.cell as arc<HttpsData>;
  if s.failure != nil {
    return s.failure as HttpsClientError;
  }

  if !s.published_complete {
    return https_protocol(s, HttpError{kind: HttpErrorKind.InvalidState});
  }

  if s.streaming {
    return https_stream_shutdown(s);
  }

  let result: Result<TlsTransfer, TlsStreamError> = https_wait(s.stream, s.stream.ShutdownAsync(s.options));
  if result.IsErr() {
    return https_fail(s, https_provider(s,(result.get_if<TlsStreamError>()) as TlsStreamError));
  }

  let transfer: TlsTransfer = (result.get_if<TlsTransfer>()) as TlsTransfer;
  if transfer.error != nil {
    return https_fail(s, https_provider(s, transfer.error as TlsStreamError));
  }

  self.Close();

  return Unit{};
}

/** @brief Abort-close once while keeping the original failure intact. */
pub method(HttpsClient) Close() -> void {
  if self.cell == nil {
    return;
  }

  let s: arc<HttpsData> = self.cell as arc<HttpsData>;
  if s.failure == nil {
    let ignored: HttpsClientError = https_fail(s, https_protocol(s, HttpError{kind: HttpErrorKind.Closed}));
  }
}

/**
 * @brief Validate a request and open an https URL using explicit bounded DNS and one original
 *   control budget.
 * @returns Ok with HttpsClient on success; Err with HttpsClientError on the failure paths
 *   described above.
 * @note Derive Host, target and certificate/SNI identity from URL. Config peer_name may be empty
 *   or match that host; explicit CA trust remains required. Only http/1.1 ALPN is supported. DNS
 *   workers remain caller-owned; the call drives a private notification loop without busy waiting.
 *   Invalid request/identity/ALPN fails before dialing. No redirects, proxy, downgrade or pooling.
 */
pub static method(HttpsClient) Open(
  url: ref HttpUrl,
  config: ref TlsClientConfig,
  verb: ref string,
  fields: ref <HttpField>[],
  body: ref NetBuffer,
  limits: ref HttpClientLimits,
  resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions,
  options: ref NetOperationOptions
) -> Result<HttpsClient, HttpsClientError> {
  let control: Result<Unit, NetError> = options.Check(NetClock.NowNanoseconds());
  if control.IsErr() {
    return HttpsClientError{
      tls_error: https_control((control.get_if<NetError>()) as NetError),
      stage: HttpClientStage.Resolve
    };
  }

  if !url.IsValid() || !url.IsSecure() {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}};
  }

  if config.peer_name.length != 0 && !https_identity(url.Host(), config.peer_name) {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}};
  }

  if config.alpn.length != 0 && !config.alpn.Equal("http/1.1") {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.Unsupported}};
  }

  let head: Result<NetBuffer, HttpError> = url.RequestHead(verb, fields, body.Len() as uint64);
  if head.IsErr() {
    return HttpsClientError{protocol_error:(head.get_if<HttpError>()) as HttpError};
  }

  let wire: NetBuffer = (head.get_if<NetBuffer>()) as NetBuffer;
  var validated: Result<HttpClientExchange, HttpError> = HttpClientExchange.New(wire, body, limits);
  if validated.IsErr() {
    return HttpsClientError{protocol_error:(validated.get_if<HttpError>()) as HttpError};
  }

  validated = HttpError{kind: HttpErrorKind.Closed};
  var connected: Result<TcpConnection, HttpClientError> = url.Dial(resolver, dial, options);
  if connected.IsErr() {
    let error: HttpClientError = (connected.get_if<HttpClientError>()) as HttpClientError;
    if error.transport_error != nil {
      return HttpsClientError{
        tls_error: https_control(error.transport_error as NetError),
        stage: error.stage,
        stats: error.stats
      };
    }

    return HttpsClientError{protocol_error: error.protocol_error, stage: error.stage, stats: error.stats};
  }

  var connection: TcpConnection = move((connected.get_if<TcpConnection>()) as TcpConnection);
  var settings: TlsClientConfig = config;
  settings.peer_name = url.Host();

  return HttpsClient.New(connection, settings, wire, body, limits, options);
}

/**
 * @brief Open a streamed HTTPS URL using caller-owned DNS and the original absolute controls.
 * @param plan Same request framing profile as HttpUrl.StreamingRequestHead.
 * @param continue_wait_ms Finite 0..60000 ms fallback after verified head ciphertext is flushed.
 * @returns Ok with HttpsClient on success; Err with HttpsClientError on the failure paths
 *   described above.
 * @note URL supplies Host, target and peer/SNI identity. Empty config peer_name is filled from
 *   URL; another identity or unsupported ALPN fails before DNS, as do request/limits/continue
 *   errors. Explicit CA/provider/channel resources are validated after dial and before HTTP
 *   output. Next/SupplyBody/FinishBody match NewStreaming. Producer time shares the original
 *   deadline. No automatic redirect or producer replay; immutable Open/OpenRequest remain
 *   unchanged.
 */
pub static method(HttpsClient) OpenStreaming(
  url: ref HttpUrl,
  config: ref TlsClientConfig,
  verb: ref string,
  fields: ref <HttpField>[],
  plan: ref HttpBodyPlan,
  limits: ref HttpClientLimits,
  resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions,
  options: ref NetOperationOptions,
  continue_wait_ms: int32
) -> Result<HttpsClient, HttpsClientError> {
  let control: Result<Unit, NetError> = options.Check(NetClock.NowNanoseconds());
  if control.IsErr() {
    return HttpsClientError{
      tls_error: https_control((control.get_if<NetError>()) as NetError),
      stage: HttpClientStage.Resolve
    };
  }

  if !url.IsValid() || !url.IsSecure() {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}};
  }

  if config.peer_name.length != 0 && !https_identity(url.Host(), config.peer_name) {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}};
  }

  if config.alpn.length != 0 && !config.alpn.Equal("http/1.1") {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.Unsupported}};
  }

  if continue_wait_ms < 0 || continue_wait_ms > 60000 {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}};
  }

  let head: Result<NetBuffer, HttpError> = url.StreamingRequestHead(verb, fields, plan);
  if head.IsErr() {
    return HttpsClientError{protocol_error:(head.get_if<HttpError>()) as HttpError};
  }

  let wire: NetBuffer = (head.get_if<NetBuffer>()) as NetBuffer;
  var validated: Result<HttpClientExchange, HttpError> = HttpClientExchange.NewStreaming(wire, limits);
  if validated.IsErr() {
    return HttpsClientError{protocol_error:(validated.get_if<HttpError>()) as HttpError};
  }

  validated = HttpError{kind: HttpErrorKind.Closed};
  var connected: Result<TcpConnection, HttpClientError> = url.Dial(resolver, dial, options);
  if connected.IsErr() {
    let error: HttpClientError = (connected.get_if<HttpClientError>()) as HttpClientError;
    if error.transport_error != nil {
      return HttpsClientError{
        tls_error: https_control(error.transport_error as NetError),
        stage: error.stage,
        stats: error.stats
      };
    }

    return HttpsClientError{protocol_error: error.protocol_error, stage: error.stage, stats: error.stats};
  }

  var connection: TcpConnection = move((connected.get_if<TcpConnection>()) as TcpConnection);
  var settings: TlsClientConfig = config;
  settings.peer_name = url.Host();

  return HttpsClient.NewStreaming(connection, settings, wire, limits, options, continue_wait_ms);
}

/**
 * @brief Open a redirect snapshot with its retained original controls and URL-derived peer
 *   identity.
 * @returns Ok with HttpsClient on success; Err with HttpsClientError on the failure paths
 *   described above.
 * @note Reject streamed snapshots; use OpenStreamingRequest. Caller explicitly closes the
 *   previous client after an accepted Follow. Config peer_name may be empty or match this hop; no
 *   transport failure is automatically retried or redirected.
 */
pub static method(HttpsClient) OpenRequest(
  request: ref HttpRedirectRequest,
  config: ref TlsClientConfig,
  resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions
) -> Result<HttpsClient, HttpsClientError> {
  if request.IsStreaming() {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidState}};
  }

  var fields: owned <HttpField>[] = new <HttpField>[request.FieldCount()];
  var i: int32 = 0;
  while i < fields.length {
    fields[i] = (request.FieldAt(i).get_if<HttpField>()) as HttpField;
    i = i + 1;
  }

  return HttpsClient.Open(
    request.Url(),
    config,
    request.Verb(),
    fields,
    request.Body(),
    request.Limits(),
    resolver,
    dial,
    request.Options()
  );
}

/**
 * @brief Open only a streamed redirect snapshot under original controls and URL-derived TLS
 *   identity.
 * @returns Ok with HttpsClient on success; Err with HttpsClientError on the failure paths
 *   described above.
 * @note Caller prepares an identical producer before preserved-body replay. Immutable
 *   OpenRequest rejects streamed snapshots; this method rejects immutable/default snapshots
 *   without I/O.
 */
pub static method(HttpsClient) OpenStreamingRequest(
  request: ref HttpRedirectRequest,
  config: ref TlsClientConfig,
  resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions,
  continue_wait_ms: int32
) -> Result<HttpsClient, HttpsClientError> {
  if !request.IsStreaming() {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidState}};
  }

  var fields: owned <HttpField>[] = new <HttpField>[request.FieldCount()];
  var i: int32 = 0;
  while i < fields.length {
    fields[i] = (request.FieldAt(i).get_if<HttpField>()) as HttpField;
    i = i + 1;
  }

  return HttpsClient.OpenStreaming(
    request.Url(),
    config,
    request.Verb(),
    fields,
    request.UploadPlan(),
    request.Limits(),
    resolver,
    dial,
    request.Options(),
    continue_wait_ms
  );
}
