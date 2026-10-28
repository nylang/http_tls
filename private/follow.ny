/** @brief Automatic transport selection over the shared redirect policy; no duplicate HTTP grammar. */
module HttpFollowAdapter;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "tls:tls.ny";
import "http:http.ny";
import "interface/http_tls.ni";
import "interface/follow.ni";
struct FollowData { chain: HttpRedirectChain; request: HttpRedirectRequest; config: TlsClientConfig; dial: HttpDialOptions; tcp: HttpTcpClient; https: HttpsClient; opened: bool; secure: bool; complete: bool; stats: HttpClientStats; failure: HttpFollowError?; }
pub struct HttpFollowClient { cell: arc<FollowData>?; }
func follow_http(s: arc<FollowData>, error: HttpClientError) -> HttpFollowError { return HttpFollowError{http_error: error, redirect_count: s.chain.Count(), url: s.request.Url()}; }
func follow_https(s: arc<FollowData>, error: HttpsClientError) -> HttpFollowError { return HttpFollowError{https_error: error, redirect_count: s.chain.Count(), url: s.request.Url()}; }
func follow_protocol(s: arc<FollowData>, kind: HttpErrorKind) -> HttpFollowError { return follow_http(s, HttpClientError{protocol_error: HttpError{kind: kind}, stage: HttpClientStage.ResponseHead, stats: s.stats}); }
func follow_closed() -> HttpFollowError { return HttpFollowError{http_error: HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.Closed}}}; }
func follow_retire(state: arc<FollowData>) -> void { var s: arc<FollowData> = state; s.tcp.Close(); s.https.Close(); s.tcp = HttpTcpClient{}; s.https = HttpsClient{}; s.opened = false; }
func follow_fail(state: arc<FollowData>, error: HttpFollowError) -> HttpFollowError { var s: arc<FollowData> = state; if s.failure != nil { return s.failure as HttpFollowError; } follow_retire(s); s.failure = error; return error; }
func follow_copy(text: ref string) -> string { var buffer: StringBuffer = StringBuffer.New(); buffer.Append(text); return buffer.Take(); }
/** @brief Validate and retain an initial request before any DNS, TCP or TLS work. */
pub static method(HttpFollowClient) New(url: ref HttpUrl, config: ref TlsClientConfig, verb: ref string, fields: ref <HttpField>[], body: ref NetBuffer, limits: ref HttpClientLimits, policy: ref HttpRedirectPolicy, dial: ref HttpDialOptions, options: ref NetOperationOptions) -> Result<HttpFollowClient, HttpFollowError> {
  var made: Result<HttpRedirectChain, HttpClientError> = HttpRedirectChain.New(url, verb, fields, body, limits, policy, options);
  if made.IsErr() { return HttpFollowError{http_error: (made.get_if<HttpClientError>()) as HttpClientError, url: url}; }
  var chain: HttpRedirectChain = move((made.get_if<HttpRedirectChain>()) as HttpRedirectChain);
  let request: Result<HttpRedirectRequest, HttpClientError> = chain.Request();
  if request.IsErr() { return HttpFollowError{http_error: (request.get_if<HttpClientError>()) as HttpClientError, url: url}; }
  let settings: TlsClientConfig = TlsClientConfig{peer_name: follow_copy(config.peer_name), ca_file: follow_copy(config.ca_file), alpn: follow_copy(config.alpn), ciphertext_capacity: config.ciphertext_capacity};
  return HttpFollowClient{cell: new arc<FollowData>{chain: move(chain), request: (request.get_if<HttpRedirectRequest>()) as HttpRedirectRequest, config: settings, dial: dial}};
}
/** @brief Transfer cursor and transport ownership. */
pub method(HttpFollowClient) operator move() -> HttpFollowClient { let cell: arc<FollowData>? = self.cell; self.cell = nil; return HttpFollowClient{cell: cell}; }
/** @brief Abort-close retained transports. */
pub method(HttpFollowClient) operator drop() -> void { self.Close(); self.cell = nil; }
/** @brief Drive the current transport and replace it only after an accepted redirect decision. */
pub method(HttpFollowClient) Next(resolver: ref mut AsyncResolver) -> Result<HttpClientEvent, HttpFollowError> {
  if self.cell == nil { return follow_closed(); } var s: arc<FollowData> = self.cell as arc<FollowData>;
  if s.failure != nil { return s.failure as HttpFollowError; }
  if s.complete { return HttpClientEvent{kind: HttpClientEventKind.Complete, complete: true, stats: s.stats}; }
  while true {
    if !s.opened {
      s.secure = s.request.Url().IsSecure();
      if s.secure {
        var opened: Result<HttpsClient, HttpsClientError> = HttpsClient.OpenRequest(s.request, s.config, resolver, s.dial);
        if opened.IsErr() { return follow_fail(s, follow_https(s, (opened.get_if<HttpsClientError>()) as HttpsClientError)); }
        s.https = move((opened.get_if<HttpsClient>()) as HttpsClient);
      } else {
        var opened: Result<HttpTcpClient, HttpClientError> = s.request.OpenTcp(resolver, s.dial);
        if opened.IsErr() { return follow_fail(s, follow_http(s, (opened.get_if<HttpClientError>()) as HttpClientError)); }
        s.tcp = move((opened.get_if<HttpTcpClient>()) as HttpTcpClient);
      }
      s.opened = true;
    }
    var event: HttpClientEvent = HttpClientEvent{};
    if s.secure {
      let advanced: Result<HttpClientEvent, HttpsClientError> = s.https.Next();
      if advanced.IsErr() { return follow_fail(s, follow_https(s, (advanced.get_if<HttpsClientError>()) as HttpsClientError)); }
      event = (advanced.get_if<HttpClientEvent>()) as HttpClientEvent;
    } else {
      let advanced: Result<HttpClientEvent, HttpClientError> = s.tcp.Next();
      if advanced.IsErr() { return follow_fail(s, follow_http(s, (advanced.get_if<HttpClientError>()) as HttpClientError)); }
      event = (advanced.get_if<HttpClientEvent>()) as HttpClientEvent;
    }
    s.stats = event.stats;
    if event.kind == HttpClientEventKind.Head {
      let decision: Result<bool, HttpClientError> = s.chain.Follow(event.head);
      if decision.IsErr() {
        var error: HttpClientError = (decision.get_if<HttpClientError>()) as HttpClientError; error.stats = s.stats;
        return follow_fail(s, follow_http(s, error));
      }
      if (decision.get_if<bool>()) as bool {
        follow_retire(s);
        let request: Result<HttpRedirectRequest, HttpClientError> = s.chain.Request();
        if request.IsErr() { return follow_fail(s, follow_http(s, (request.get_if<HttpClientError>()) as HttpClientError)); }
        s.request = (request.get_if<HttpRedirectRequest>()) as HttpRedirectRequest; s.stats = HttpClientStats{}; continue;
      }
    }
    s.complete = event.complete; return event;
  }
}
/** @brief Retain the current request's URL independently of connection state. */
pub method(HttpFollowClient) Url() -> HttpUrl { if self.cell == nil { return HttpUrl{}; } return (self.cell as arc<FollowData>).request.Url(); }
/** @brief Count only committed redirect decisions. */
pub method(HttpFollowClient) RedirectCount() -> int32 { if self.cell == nil { return 0; } return (self.cell as arc<FollowData>).chain.Count(); }
/** @brief Delegate trailers only after terminal completion. */
pub method(HttpFollowClient) TrailerCount() -> Result<int32, HttpFollowError> {
  if self.cell == nil { return follow_closed(); } let s: arc<FollowData> = self.cell as arc<FollowData>;
  if s.failure != nil { return s.failure as HttpFollowError; } if !s.complete { return follow_protocol(s, HttpErrorKind.InvalidState); }
  if s.secure { let result: Result<int32, HttpsClientError> = s.https.TrailerCount(); if result.IsErr() { return follow_https(s, (result.get_if<HttpsClientError>()) as HttpsClientError); } return (result.get_if<int32>()) as int32; }
  let result: Result<int32, HttpClientError> = s.tcp.TrailerCount(); if result.IsErr() { return follow_http(s, (result.get_if<HttpClientError>()) as HttpClientError); } return (result.get_if<int32>()) as int32;
}
/** @brief Retain one owned terminal response trailer. */
pub method(HttpFollowClient) TrailerAt(index: int32) -> Result<HttpField, HttpFollowError> {
  if self.cell == nil { return follow_closed(); } let s: arc<FollowData> = self.cell as arc<FollowData>;
  if s.failure != nil { return s.failure as HttpFollowError; } if !s.complete { return follow_protocol(s, HttpErrorKind.InvalidState); }
  if s.secure { let result: Result<HttpField, HttpsClientError> = s.https.TrailerAt(index); if result.IsErr() { return follow_https(s, (result.get_if<HttpsClientError>()) as HttpsClientError); } return (result.get_if<HttpField>()) as HttpField; }
  let result: Result<HttpField, HttpClientError> = s.tcp.TrailerAt(index); if result.IsErr() { return follow_http(s, (result.get_if<HttpClientError>()) as HttpClientError); } return (result.get_if<HttpField>()) as HttpField;
}
/** @brief Gracefully retire a completed response using its selected transport. */
pub method(HttpFollowClient) Shutdown() -> Result<Unit, HttpFollowError> {
  if self.cell == nil { return follow_closed(); } let s: arc<FollowData> = self.cell as arc<FollowData>;
  if s.failure != nil { return s.failure as HttpFollowError; } if !s.complete { return follow_protocol(s, HttpErrorKind.InvalidState); }
  if s.secure { let result: Result<Unit, HttpsClientError> = s.https.Shutdown(); if result.IsErr() { return follow_fail(s, follow_https(s, (result.get_if<HttpsClientError>()) as HttpsClientError)); } }
  self.Close(); return Unit{};
}
/** @brief Abort once and preserve the first terminal failure. */
pub method(HttpFollowClient) Close() -> void { if self.cell == nil { return; } let s: arc<FollowData> = self.cell as arc<FollowData>; if s.failure == nil { let ignored: HttpFollowError = follow_fail(s, follow_protocol(s, HttpErrorKind.Closed)); } }
