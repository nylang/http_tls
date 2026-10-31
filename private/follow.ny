// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/**
 * @brief Automatic transport selection over the shared redirect policy; no duplicate HTTP
 *   grammar.
 */
module HttpFollowAdapter;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "tls:tls.ny";
import "http:http.ny";
import "interface/http_tls.ni";
import "interface/follow.ni";
import "private/http_tls.ny";

struct FollowData {
  chain: HttpRedirectChain;
  request: HttpRedirectRequest;
  config: TlsClientConfig;
  dial: HttpDialOptions;
  tcp: HttpTcpClient;
  https: HttpsClient;
  opened: bool;
  streaming: bool;
  replay_pending: bool;
  continue_wait_ms: int32;
  secure: bool;
  complete: bool;
  stats: HttpClientStats;
  failure: HttpFollowError?;
}

/**
 * @brief Move-only single-caller automatic redirect cursor; no transport retries or connection
 *   reuse.
 */
pub struct HttpFollowClient {
  cell: arc<FollowData>?;
}

method(FollowData) HttpError(error: HttpClientError) -> HttpFollowError {
  return HttpFollowError{http_error: error, redirect_count: self.chain.Count(), url: self.request.Url()};
}

method(FollowData) HttpsError(error: HttpsClientError) -> HttpFollowError {
  return HttpFollowError{https_error: error, redirect_count: self.chain.Count(), url: self.request.Url()};
}

method(FollowData) ProtocolError(kind: HttpErrorKind) -> HttpFollowError {
  return self.HttpError(HttpClientError{
      protocol_error: HttpError{kind: kind},
      stage: HttpClientStage.ResponseHead,
      stats: self.stats
    });
}

static method(HttpFollowError) Closed() -> HttpFollowError {
  return HttpFollowError{http_error: HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.Closed}}};
}

method(FollowData) Retire() -> void {
  self.tcp.Close();
  self.https.Close();
  self.tcp = HttpTcpClient{};
  self.https = HttpsClient{};
  self.opened = false;
}

method(FollowData) Fail(error: HttpFollowError) -> HttpFollowError {
  if self.failure != nil {
    return self.failure as HttpFollowError;
  }

  self.Retire();
  self.failure = error;

  return error;
}

/**
 * @brief Own a validated request, redirect policy, copied TLS strings and original controls
 *   without I/O.
 * @returns Ok with HttpFollowClient on success; Err with HttpFollowError on the failure paths
 *   described above.
 * @note Next explicitly borrows the caller's resolver; keep using the same bounded pool. Dial
 *   settings and absolute deadline/shared cancellation are retained for every hop. Empty
 *   config.peer_name derives identity from each URL; a fixed peer must match every HTTPS hop.
 *   Explicit CA trust is required on HTTPS. TCP-only applications can use http without importing
 *   this optional package.
 */
pub static method(HttpFollowClient) New(
  url: ref HttpUrl,
  config: ref TlsClientConfig,
  verb: ref string,
  fields: ref <HttpField>[],
  body: ref NetBuffer,
  limits: ref HttpClientLimits,
  policy: ref HttpRedirectPolicy,
  dial: ref HttpDialOptions,
  options: ref NetOperationOptions
) -> Result<HttpFollowClient, HttpFollowError> {
  var made: Result<HttpRedirectChain, HttpClientError> = HttpRedirectChain.New(
    url,
    verb,
    fields,
    body,
    limits,
    policy,
    options
  );
  if made.IsErr() {
    return HttpFollowError{http_error:(made.get_if<HttpClientError>()) as HttpClientError, url: url};
  }

  var chain: HttpRedirectChain = move((made.get_if<HttpRedirectChain>()) as HttpRedirectChain);
  let request: Result<HttpRedirectRequest, HttpClientError> = chain.Request();
  if request.IsErr() {
    return HttpFollowError{http_error:(request.get_if<HttpClientError>()) as HttpClientError, url: url};
  }

  let settings: TlsClientConfig = TlsClientConfig{
    peer_name: (config.peer_name).Substring(0, (config.peer_name).length),
    ca_file: (config.ca_file).Substring(0, (config.ca_file).length),
    alpn: (config.alpn).Substring(0, (config.alpn).length),
    ciphertext_capacity: config.ciphertext_capacity
  };

  return HttpFollowClient{cell: new arc<FollowData>{
    chain: move(chain),
    request:(request.get_if<HttpRedirectRequest>()) as HttpRedirectRequest,
    config: settings,
    dial: dial
  }};
}

/**
 * @brief Own a streamed request and lazily follow redirects with explicit producer replay
 *   acknowledgement.
 * @returns Ok with HttpFollowClient on success; Err with HttpFollowError on the failure paths
 *   described above.
 * @note Plan, limits and continue_wait_ms match URL streaming. No body is buffered for replay.
 *   Rewrites to empty GET continue without a producer. Preserved nonempty/chunked requests require
 *   both allow_unsafe_replay and Explicit replay permission, even if an early final sent no
 *   payload. After an accepted preserved-body redirect, close the old transport, update
 *   Url/RedirectCount, and emit NeedReplay repeatedly without DNS or connection I/O. Caller
 *   rewinds an identical payload/trailer producer and calls ReplayBody before Next may open the
 *   new hop. The original deadline/token includes rewind time. There is no automatic transport
 *   retry.
 */
pub static method(HttpFollowClient) NewStreaming(
  url: ref HttpUrl,
  config: ref TlsClientConfig,
  verb: ref string,
  fields: ref <HttpField>[],
  plan: ref HttpBodyPlan,
  limits: ref HttpClientLimits,
  policy: ref HttpRedirectPolicy,
  replay: HttpBodyReplayPolicy,
  dial: ref HttpDialOptions,
  options: ref NetOperationOptions,
  continue_wait_ms: int32
) -> Result<HttpFollowClient, HttpFollowError> {
  let control: Result<Unit, NetError> = options.CheckNow();
  if control.IsErr() {
    return HttpFollowError{
      http_error: HttpClientError{transport_error:(control.get_if<NetError>()) as NetError},
      url: url
    };
  }

  if continue_wait_ms < 0 || continue_wait_ms > 60000 {
    return HttpFollowError{
      http_error: HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}},
      url: url
    };
  }

  var made: Result<HttpRedirectChain, HttpClientError> = HttpRedirectChain.NewStreaming(
    url,
    verb,
    fields,
    plan,
    limits,
    policy,
    replay,
    options
  );
  if made.IsErr() {
    return HttpFollowError{http_error:(made.get_if<HttpClientError>()) as HttpClientError, url: url};
  }

  var chain: HttpRedirectChain = move((made.get_if<HttpRedirectChain>()) as HttpRedirectChain);
  let request: Result<HttpRedirectRequest, HttpClientError> = chain.Request();
  if request.IsErr() {
    return HttpFollowError{http_error:(request.get_if<HttpClientError>()) as HttpClientError, url: url};
  }

  let settings: TlsClientConfig = TlsClientConfig{
    peer_name: (config.peer_name).Substring(0, (config.peer_name).length),
    ca_file: (config.ca_file).Substring(0, (config.ca_file).length),
    alpn: (config.alpn).Substring(0, (config.alpn).length),
    ciphertext_capacity: config.ciphertext_capacity
  };

  return HttpFollowClient{cell: new arc<FollowData>{
    chain: move(chain),
    request:(request.get_if<HttpRedirectRequest>()) as HttpRedirectRequest,
    config: settings,
    dial: dial,
    streaming: true,
    continue_wait_ms: continue_wait_ms
  }};
}

method(FollowData) ControlError() -> HttpFollowError? {
  let checked: Result<Unit, NetError> = self.request.Options().CheckNow();
  if checked.IsErr() {
    return self.Fail(self.HttpError(HttpClientError{
          transport_error:(checked.get_if<NetError>()) as NetError,
          stage: HttpClientStage.Request
        }));
  }

  return nil;
}

method(HttpRedirectRequest) HasReplayBody() -> bool {
  let plan: HttpBodyPlan = self.UploadPlan();

  return self.IsStreaming()
    && (
      plan.kind == HttpBodyKind.Chunked || (plan.kind == HttpBodyKind.ContentLength && plan.length != 0u64)
    );
}

/**
 * @brief Transfer the sole cursor and current transport.
 * @returns The HttpFollowClient value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpFollowClient) operator move() -> HttpFollowClient {
  let cell: arc<FollowData>? = self.cell;
  self.cell = nil;

  return HttpFollowClient{cell: cell};
}

/** @brief Abort-close retained transports. */
pub method(HttpFollowClient) operator drop() -> void {
  self.Close();
  self.cell = nil;
}

/**
 * @brief Open lazily and pull events, following accepted redirects before publishing their
 *   heads/bodies.
 * @returns Ok with HttpClientEvent on success; Err with HttpFollowError on the failure paths
 *   described above.
 * @note Informational events remain observable at the current Url/RedirectCount. Terminal
 *   heads/body chunks and trailers retain ordinary ownership. Close each old connection before
 *   opening the next; never drain a redirect body. HTTPS downgrade and unsafe replay remain policy
 *   errors. Failures stick and retire the connection. Completed Next calls return Complete without
 *   I/O or control refresh until explicit Close/Shutdown; no automatic transport retry is
 *   performed.
 */
pub method(HttpFollowClient) Next(
  resolver: ref mut AsyncResolver
) -> Result<HttpClientEvent, HttpFollowError> {
  if self.cell == nil {
    return HttpFollowError.Closed();
  }

  var s: arc<FollowData> = self.cell as arc<FollowData>;
  if s.failure != nil {
    return s.failure as HttpFollowError;
  }

  if s.complete {
    return HttpClientEvent{kind: HttpClientEventKind.Complete, complete: true, stats: s.stats};
  }

  while true {
    if s.replay_pending {
      let checked: HttpFollowError? = (s).ControlError();
      if checked != nil {
        return checked as HttpFollowError;
      }

      return HttpClientEvent{kind: HttpClientEventKind.NeedReplay, stats: s.stats};
    }

    if !s.opened {
      s.secure = s.request.Url().IsSecure();
      if s.secure {
        var opened: Result<HttpsClient, HttpsClientError> = HttpsClientError{
          protocol_error: HttpError{kind: HttpErrorKind.Closed}
        };
        if s.streaming {
          opened = HttpsClient.OpenStreamingRequest(
            s.request,
            s.config,
            resolver,
            s.dial,
            s.continue_wait_ms
          );
        } else {
          opened = HttpsClient.OpenRequest(s.request, s.config, resolver, s.dial);
        }

        if opened.IsErr() {
          return (s).Fail((s).HttpsError((opened.get_if<HttpsClientError>()) as HttpsClientError));
        }

        s.https = move((opened.get_if<HttpsClient>()) as HttpsClient);
      } else {
        var opened: Result<HttpTcpClient, HttpClientError> = HttpClientError{
          protocol_error: HttpError{kind: HttpErrorKind.Closed}
        };
        if s.streaming {
          opened = s.request.OpenStreamingTcp(resolver, s.dial, s.continue_wait_ms);
        } else {
          opened = s.request.OpenTcp(resolver, s.dial);
        }

        if opened.IsErr() {
          return (s).Fail((s).HttpError((opened.get_if<HttpClientError>()) as HttpClientError));
        }

        s.tcp = move((opened.get_if<HttpTcpClient>()) as HttpTcpClient);
      }

      s.opened = true;
    }

    var event: HttpClientEvent = HttpClientEvent{};
    if s.secure {
      let advanced: Result<HttpClientEvent, HttpsClientError> = s.https.Next();
      if advanced.IsErr() {
        return (s).Fail((s).HttpsError((advanced.get_if<HttpsClientError>()) as HttpsClientError));
      }

      event = (advanced.get_if<HttpClientEvent>()) as HttpClientEvent;
    } else {
      let advanced: Result<HttpClientEvent, HttpClientError> = s.tcp.Next();
      if advanced.IsErr() {
        return (s).Fail((s).HttpError((advanced.get_if<HttpClientError>()) as HttpClientError));
      }

      event = (advanced.get_if<HttpClientEvent>()) as HttpClientEvent;
    }

    s.stats = event.stats;
    if event.kind == HttpClientEventKind.Head {
      let decision: Result<bool, HttpClientError> = s.chain.Follow(event.head);
      if decision.IsErr() {
        var error: HttpClientError = (decision.get_if<HttpClientError>()) as HttpClientError;
        error.stats = s.stats;

        return (s).Fail((s).HttpError(error));
      }

      if (decision.get_if<bool>()) as bool {
        (s).Retire();
        let request: Result<HttpRedirectRequest, HttpClientError> = s.chain.Request();
        if request.IsErr() {
          return (s).Fail((s).HttpError((request.get_if<HttpClientError>()) as HttpClientError));
        }

        s.request = (request.get_if<HttpRedirectRequest>()) as HttpRedirectRequest;
        s.stats = HttpClientStats{};
        s.replay_pending = s.streaming && (s.request).HasReplayBody();
        continue;
      }
    }

    s.complete = event.complete;

    return event;
  }
}

/**
 * @brief Current hop URL; a rejected redirect retains the originating response URL.
 * @returns The HttpUrl value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpFollowClient) Url() -> HttpUrl {
  if self.cell == nil {
    return HttpUrl{};
  }

  return (self.cell as arc<FollowData>).request.Url();
}

/**
 * @brief Committed redirect count, excluding the initial request and rejected decisions.
 * @returns Committed redirect count, excluding the initial request and rejected decisions.
 */
pub method(HttpFollowClient) RedirectCount() -> int32 {
  if self.cell == nil {
    return 0;
  }

  return (self.cell as arc<FollowData>).chain.Count();
}

/**
 * @brief Terminal response trailer count; pending state returns InvalidState without retiring
 *   the cursor.
 * @returns Ok with int32 on success; Err with HttpFollowError on the failure paths described
 *   above.
 */
pub method(HttpFollowClient) TrailerCount() -> Result<int32, HttpFollowError> {
  if self.cell == nil {
    return HttpFollowError.Closed();
  }

  let s: arc<FollowData> = self.cell as arc<FollowData>;
  if s.failure != nil {
    return s.failure as HttpFollowError;
  }

  if !s.complete {
    return (s).ProtocolError(HttpErrorKind.InvalidState);
  }

  if s.secure {
    let result: Result<int32, HttpsClientError> = s.https.TrailerCount();
    if result.IsErr() {
      return (s).HttpsError((result.get_if<HttpsClientError>()) as HttpsClientError);
    }

    return (result.get_if<int32>()) as int32;
  }

  let result: Result<int32, HttpClientError> = s.tcp.TrailerCount();
  if result.IsErr() {
    return (s).HttpError((result.get_if<HttpClientError>()) as HttpClientError);
  }

  return (result.get_if<int32>()) as int32;
}

/**
 * @brief Retain one owned terminal response trailer, or a nonterminal/index error.
 * @returns Ok with HttpField on success; Err with HttpFollowError on the failure paths described
 *   above.
 */
pub method(HttpFollowClient) TrailerAt(index: int32) -> Result<HttpField, HttpFollowError> {
  if self.cell == nil {
    return HttpFollowError.Closed();
  }

  let s: arc<FollowData> = self.cell as arc<FollowData>;
  if s.failure != nil {
    return s.failure as HttpFollowError;
  }

  if !s.complete {
    return (s).ProtocolError(HttpErrorKind.InvalidState);
  }

  if s.secure {
    let result: Result<HttpField, HttpsClientError> = s.https.TrailerAt(index);
    if result.IsErr() {
      return (s).HttpsError((result.get_if<HttpsClientError>()) as HttpsClientError);
    }

    return (result.get_if<HttpField>()) as HttpField;
  }

  let result: Result<HttpField, HttpClientError> = s.tcp.TrailerAt(index);
  if result.IsErr() {
    return (s).HttpError((result.get_if<HttpClientError>()) as HttpClientError);
  }

  return (result.get_if<HttpField>()) as HttpField;
}

/**
 * @brief After HTTP completion, close TCP or complete TLS close_notify under the original
 *   controls.
 * @returns Ok with Unit on success; Err with HttpFollowError on the failure paths described
 *   above.
 * @note Pending responses return InvalidState; shutdown failures stick and retire the transport.
 */
pub method(HttpFollowClient) Shutdown() -> Result<Unit, HttpFollowError> {
  if self.cell == nil {
    return HttpFollowError.Closed();
  }

  let s: arc<FollowData> = self.cell as arc<FollowData>;
  if s.failure != nil {
    return s.failure as HttpFollowError;
  }

  if !s.complete {
    return (s).ProtocolError(HttpErrorKind.InvalidState);
  }

  if s.secure {
    let result: Result<Unit, HttpsClientError> = s.https.Shutdown();
    if result.IsErr() {
      return (s).Fail((s).HttpsError((result.get_if<HttpsClientError>()) as HttpsClientError));
    }
  }

  self.Close();

  return Unit{};
}

/** @brief Abort once and preserve the first terminal failure. */
pub method(HttpFollowClient) Close() -> void {
  if self.cell == nil {
    return;
  }

  let s: arc<FollowData> = self.cell as arc<FollowData>;
  if s.failure == nil {
    let ignored: HttpFollowError = (s).Fail((s).ProtocolError(HttpErrorKind.Closed));
  }
}

/**
 * @brief Retain immutable current-hop metadata, including streamed plan and filtered fields.
 * @returns Ok with HttpRedirectRequest on success; Err with HttpFollowError on the failure paths
 *   described above.
 * @note No producer bytes are retained. Snapshot outlives cursor changes; explicit failure is
 *   preserved.
 */
pub method(HttpFollowClient) Request() -> Result<HttpRedirectRequest, HttpFollowError> {
  if self.cell == nil {
    return HttpFollowError.Closed();
  }

  let s: arc<FollowData> = self.cell as arc<FollowData>;
  if s.failure != nil {
    return s.failure as HttpFollowError;
  }

  return s.request;
}

/**
 * @brief Acknowledge one pending NeedReplay after rewinding an identical producer; performs no
 *   I/O.
 * @returns Ok with Unit on success; Err with HttpFollowError on the failure paths described
 *   above.
 * @note Before/after the pending state returns nonterminal InvalidState. Cancellation/expiry
 *   retires the cursor. Never call merely to retry a transport failure; such failures remain
 *   terminal.
 */
pub method(HttpFollowClient) ReplayBody() -> Result<Unit, HttpFollowError> {
  if self.cell == nil {
    return HttpFollowError.Closed();
  }

  var s: arc<FollowData> = self.cell as arc<FollowData>;
  if s.failure != nil {
    return s.failure as HttpFollowError;
  }

  let checked: HttpFollowError? = (s).ControlError();
  if checked != nil {
    return checked as HttpFollowError;
  }

  if !s.replay_pending {
    return (s).ProtocolError(HttpErrorKind.InvalidState);
  }

  s.replay_pending = false;

  return Unit{};
}

/**
 * @brief Active opened streamed producer state; pending replay/unopened/immutable returns
 *   InvalidState.
 * @returns Ok with HttpUploadState on success; Err with HttpFollowError on the failure paths
 *   described above.
 */
pub method(HttpFollowClient) UploadState() -> Result<HttpUploadState, HttpFollowError> {
  if self.cell == nil {
    return HttpFollowError.Closed();
  }

  let s: arc<FollowData> = self.cell as arc<FollowData>;
  if s.failure != nil {
    return s.failure as HttpFollowError;
  }

  if !s.streaming || !s.opened || s.replay_pending {
    return (s).ProtocolError(HttpErrorKind.InvalidState);
  }

  if s.secure {
    let result: Result<HttpUploadState, HttpsClientError> = s.https.UploadState();
    if result.IsErr() {
      return (s).HttpsError((result.get_if<HttpsClientError>()) as HttpsClientError);
    }

    return (result.get_if<HttpUploadState>()) as HttpUploadState;
  }

  let result: Result<HttpUploadState, HttpClientError> = s.tcp.UploadState();
  if result.IsErr() {
    return (s).HttpError((result.get_if<HttpClientError>()) as HttpClientError);
  }

  return (result.get_if<HttpUploadState>()) as HttpUploadState;
}

/**
 * @brief Supply one bounded owner after NeedBody; pending replay rejects admission without I/O.
 * @returns Ok with Unit on success; Err with HttpFollowError on the failure paths described
 *   above.
 */
pub method(HttpFollowClient) SupplyBody(buffer: ref NetBuffer) -> Result<Unit, HttpFollowError> {
  if self.cell == nil {
    return HttpFollowError.Closed();
  }

  let s: arc<FollowData> = self.cell as arc<FollowData>;
  if s.failure != nil {
    return s.failure as HttpFollowError;
  }

  let checked: HttpFollowError? = (s).ControlError();
  if checked != nil {
    return checked as HttpFollowError;
  }

  if !s.streaming || !s.opened || s.replay_pending {
    return (s).ProtocolError(HttpErrorKind.InvalidState);
  }

  if s.secure {
    let result: Result<Unit, HttpsClientError> = s.https.SupplyBody(buffer);
    if result.IsErr() {
      let error: HttpFollowError = (s).HttpsError((result.get_if<HttpsClientError>()) as HttpsClientError);
      if s.https.UploadState().IsErr() {
        return (s).Fail(error);
      }

      return error;
    }

    return Unit{};
  }

  let result: Result<Unit, HttpClientError> = s.tcp.SupplyBody(buffer);
  if result.IsErr() {
    let error: HttpFollowError = (s).HttpError((result.get_if<HttpClientError>()) as HttpClientError);
    if s.tcp.UploadState().IsErr() {
      return (s).Fail(error);
    }

    return error;
  }

  return Unit{};
}

/**
 * @brief Finish the active streamed producer; terminal shortages/framing failures retire the
 *   cursor.
 * @returns Ok with Unit on success; Err with HttpFollowError on the failure paths described
 *   above.
 */
pub method(HttpFollowClient) FinishBody(trailers: ref <HttpField>[]) -> Result<Unit, HttpFollowError> {
  if self.cell == nil {
    return HttpFollowError.Closed();
  }

  let s: arc<FollowData> = self.cell as arc<FollowData>;
  if s.failure != nil {
    return s.failure as HttpFollowError;
  }

  let checked: HttpFollowError? = (s).ControlError();
  if checked != nil {
    return checked as HttpFollowError;
  }

  if !s.streaming || !s.opened || s.replay_pending {
    return (s).ProtocolError(HttpErrorKind.InvalidState);
  }

  if s.secure {
    let result: Result<Unit, HttpsClientError> = s.https.FinishBody(trailers);
    if result.IsErr() {
      let error: HttpFollowError = (s).HttpsError((result.get_if<HttpsClientError>()) as HttpsClientError);
      if s.https.UploadState().IsErr() {
        return (s).Fail(error);
      }

      return error;
    }

    return Unit{};
  }

  let result: Result<Unit, HttpClientError> = s.tcp.FinishBody(trailers);
  if result.IsErr() {
    let error: HttpFollowError = (s).HttpError((result.get_if<HttpClientError>()) as HttpClientError);
    if s.tcp.UploadState().IsErr() {
      return (s).Fail(error);
    }

    return error;
  }

  return Unit{};
}
