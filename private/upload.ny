/** @brief Streamed HTTPS scheduling over the optional TLS channel; shared HTTP grammar and producers. */
part of HttpsClientAdapter;
func https_stream_control(s: arc<HttpsData>) -> HttpsClientError? {
  if s.failure!=nil { return s.failure; }
  let result: Result<Unit,NetError> = s.options.Check(NetClock.NowNanoseconds());
  if result.IsErr() { return https_fail(s,https_provider(s,https_control((result.get_if<NetError>()) as NetError))); }
  return nil;
}
/** @brief Validate all request/identity/provider settings before taking TCP ownership. */
pub static method(HttpsClient) NewStreaming(connection: ref mut TcpConnection, config: ref TlsClientConfig, head: ref NetBuffer, limits: ref HttpClientLimits, options: ref NetOperationOptions, continue_wait_ms: int32) -> Result<HttpsClient,HttpsClientError> {
  let control: Result<Unit,NetError> = options.Check(NetClock.NowNanoseconds());
  if control.IsErr() { return HttpsClientError{tls_error:https_control((control.get_if<NetError>()) as NetError)}; }
  if continue_wait_ms<0 || continue_wait_ms>60000 { return HttpsClientError{protocol_error:HttpError{kind:HttpErrorKind.InvalidArgument}}; }
  var core: Result<HttpClientExchange,HttpError> = HttpClientExchange.NewStreaming(head,limits);
  if core.IsErr() { return HttpsClientError{protocol_error:(core.get_if<HttpError>()) as HttpError}; }
  var exchange: HttpClientExchange = move((core.get_if<HttpClientExchange>()) as HttpClientExchange);
  let host: string = (exchange.AuthorityHost().get_if<string>()) as string;
  if !https_identity(host,config.peer_name) { return HttpsClientError{protocol_error:HttpError{kind:HttpErrorKind.InvalidArgument}}; }
  if config.alpn.length!=0 && !config.alpn.Equal("http/1.1") { return HttpsClientError{protocol_error:HttpError{kind:HttpErrorKind.Unsupported}}; }
  var settings: TlsClientConfig = config; settings.alpn="http/1.1";
  var channel: Result<TlsChannel,TlsStreamError> = TlsChannel.NewClient(connection,settings);
  if channel.IsErr() { return HttpsClientError{tls_error:(channel.get_if<TlsStreamError>()) as TlsStreamError}; }
  return HttpsClient{cell:new arc<HttpsData>{channel:move((channel.get_if<TlsChannel>()) as TlsChannel),exchange:move(exchange),options:options,streaming:true,continue_wait_ms:continue_wait_ms}};
}
func https_stream_wait(s: arc<HttpsData>, readable: bool, writable: bool, gate: bool) -> HttpsClientError? {
  var maximum: int32 = -1;
  if gate { maximum=s.continue_deadline.PollMilliseconds(NetClock.NowNanoseconds()); }
  let waited: Result<Unit,TlsStreamError> = s.channel.Wait(readable,writable,maximum,s.options);
  if waited.IsErr() { return https_fail(s,https_provider(s,(waited.get_if<TlsStreamError>()) as TlsStreamError)); }
  return nil;
}
func https_stream_next(state: arc<HttpsData>) -> Result<HttpClientEvent,HttpsClientError> {
  var s: arc<HttpsData> = state;
  while true {
    let control: HttpsClientError? = https_stream_control(s); if control!=nil { return control as HttpsClientError; }
    if !s.handshaken {
      let ready: Result<Unit,TlsStreamError> = s.channel.Handshake(s.options);
      if ready.IsErr() { return https_fail(s,https_provider(s,(ready.get_if<TlsStreamError>()) as TlsStreamError)); }
      let selected: Result<string,TlsStreamError> = s.channel.SelectedAlpn();
      if selected.IsErr() { return https_fail(s,https_provider(s,(selected.get_if<TlsStreamError>()) as TlsStreamError)); }
      let value: string = (selected.get_if<string>()) as string;
      if value.length!=0 && !value.Equal("http/1.1") { return https_fail(s,https_protocol(s,HttpError{kind:HttpErrorKind.Unsupported})); }
      s.handshaken=true; continue;
    }
    let queried: Result<HttpUploadState,HttpError> = s.exchange.UploadState();
    if queried.IsErr() { return https_fail(s,https_protocol(s,(queried.get_if<HttpError>()) as HttpError)); }
    var upload: HttpUploadState = (queried.get_if<HttpUploadState>()) as HttpUploadState;
    var provider_write_retry: bool=false;
    if upload!=HttpUploadState.SendingHead {
      let advanced: Result<HttpClientEvent,HttpError> = s.exchange.NextResponse();
      if advanced.IsErr() { return https_fail(s,https_protocol(s,(advanced.get_if<HttpError>()) as HttpError)); }
      let event: HttpClientEvent = (advanced.get_if<HttpClientEvent>()) as HttpClientEvent;
      if event.kind!=HttpClientEventKind.NeedInput {
        let checked: HttpsClientError? = https_stream_control(s); if checked!=nil { return checked as HttpsClientError; }
        s.published_complete=event.complete; return event;
      }
      let result: Result<TlsChannelRead,TlsStreamError> = s.channel.ReadAvailable(s.options);
      if result.IsErr() { return https_fail(s,https_provider(s,(result.get_if<TlsStreamError>()) as TlsStreamError)); }
      let read: TlsChannelRead = (result.get_if<TlsChannelRead>()) as TlsChannelRead;
      if read.transfer.error!=nil {
        var failure: HttpsClientError = https_provider(s,read.transfer.error as TlsStreamError);
        failure.stats.response_bytes_received=failure.stats.response_bytes_received+(read.transfer.bytes_transferred as uint64); return https_fail(s,failure);
      }
      if read.state==TlsChannelReadState.Again { continue; }
      if read.state==TlsChannelReadState.Ready {
        if read.transfer.bytes_transferred!=read.transfer.buffer.Len() || (read.transfer.bytes_transferred==(0 as intptr) && !read.transfer.eof) { return https_fail(s,https_protocol(s,HttpError{kind:HttpErrorKind.InvalidState})); }
        let received: Result<Unit,HttpError> = s.exchange.Receive(read.transfer.buffer,read.transfer.eof);
        if received.IsErr() { return https_fail(s,https_protocol(s,(received.get_if<HttpError>()) as HttpError)); }
        continue;
      }
      if read.state==TlsChannelReadState.NeedWrite {
        let waited: HttpsClientError? = https_stream_wait(s,false,true,false); if waited!=nil { return waited as HttpsClientError; } continue;
      }
      provider_write_retry=read.state==TlsChannelReadState.RetryWrite;
      upload=(s.exchange.UploadState().get_if<HttpUploadState>()) as HttpUploadState;
      if read.state!=TlsChannelReadState.RetryWrite {
        if upload==HttpUploadState.ReadingResponse || upload==HttpUploadState.Stopped {
          let waited: HttpsClientError? = https_stream_wait(s,true,false,false); if waited!=nil { return waited as HttpsClientError; } continue;
        }
        // Flush a previously accepted block before asking for more producer data
        // or waiting for a response. Always probe responses again after blocking.
        if upload!=HttpUploadState.SendingBody {
          let flushed: Result<bool,TlsStreamError> = s.channel.Flush(s.options);
          if flushed.IsErr() { return https_fail(s,https_provider(s,(flushed.get_if<TlsStreamError>()) as TlsStreamError)); }
          if !((flushed.get_if<bool>()) as bool) {
            let waited: HttpsClientError? = https_stream_wait(s,true,true,false); if waited!=nil { return waited as HttpsClientError; } continue;
          }
          s.head_flushed=true;
        }
        if !s.continue_started && s.head_flushed {
          s.continue_started=true; s.continue_deadline=NetDeadline.After(NetClock.NowNanoseconds(),(s.continue_wait_ms as uint64)*1000000u64);
        }
        if upload==HttpUploadState.WaitingContinue {
          if s.continue_deadline.IsExpired(NetClock.NowNanoseconds()) {
            let released: Result<Unit,HttpError> = s.exchange.ContinueUpload();
            if released.IsErr() { return https_fail(s,https_protocol(s,(released.get_if<HttpError>()) as HttpError)); }
            continue;
          }
          let waited: HttpsClientError? = https_stream_wait(s,true,false,true); if waited!=nil { return waited as HttpsClientError; } continue;
        }
        if upload==HttpUploadState.NeedBody {
          let checked: HttpsClientError? = https_stream_control(s); if checked!=nil { return checked as HttpsClientError; }
          return HttpClientEvent{kind:HttpClientEventKind.NeedBody,stats:s.exchange.Stats()};
        }
        if upload==HttpUploadState.Finished {
          let waited: HttpsClientError? = https_stream_wait(s,true,false,false); if waited!=nil { return waited as HttpsClientError; } continue;
        }
      }
    }
    let output: Result<NetBuffer,HttpError> = s.exchange.Output();
    if output.IsErr() { return https_fail(s,https_protocol(s,(output.get_if<HttpError>()) as HttpError)); }
    let block: NetBuffer = (output.get_if<NetBuffer>()) as NetBuffer;
    if block.Len()==(0 as intptr) {
      let next: HttpUploadState = (s.exchange.UploadState().get_if<HttpUploadState>()) as HttpUploadState;
      if next!=upload { continue; }
      return https_fail(s,https_protocol(s,HttpError{kind:HttpErrorKind.InvalidState}));
    }
    let sent: Result<TlsChannelWrite,TlsStreamError> = s.channel.WriteAvailable(block,s.options);
    if sent.IsErr() { return https_fail(s,https_provider(s,(sent.get_if<TlsStreamError>()) as TlsStreamError)); }
    let write: TlsChannelWrite = (sent.get_if<TlsChannelWrite>()) as TlsChannelWrite;
    let acknowledged: Result<Unit,HttpError> = s.exchange.AcknowledgeOutput(write.transfer.bytes_transferred);
    if acknowledged.IsErr() { return https_fail(s,https_protocol(s,(acknowledged.get_if<HttpError>()) as HttpError)); }
    if write.transfer.error!=nil { return https_fail(s,https_provider(s,write.transfer.error as TlsStreamError)); }
    if write.transfer.bytes_transferred>(0 as intptr) { continue; }
    if write.state==TlsChannelWriteState.RetryRead { continue; }
    let waited: HttpsClientError? = https_stream_wait(s,write.state==TlsChannelWriteState.NeedRead || (upload!=HttpUploadState.SendingHead && !provider_write_retry),write.state!=TlsChannelWriteState.NeedRead,false);
    if waited!=nil { return waited as HttpsClientError; }
  }
  return HttpsClientError{protocol_error:HttpError{kind:HttpErrorKind.InvalidState}};
}
/** @brief Query producer state without I/O or deadline renewal. */
pub method(HttpsClient) UploadState() -> Result<HttpUploadState,HttpsClientError> {
  if self.cell==nil { return HttpsClientError{protocol_error:HttpError{kind:HttpErrorKind.Closed}}; }
  let s: arc<HttpsData> = self.cell as arc<HttpsData>; if s.failure!=nil { return s.failure as HttpsClientError; }
  let result: Result<HttpUploadState,HttpError> = s.exchange.UploadState();
  if result.IsErr() { return https_protocol(s,(result.get_if<HttpError>()) as HttpError); } return (result.get_if<HttpUploadState>()) as HttpUploadState;
}
/** @brief Retain one bounded immutable producer owner without I/O. */
pub method(HttpsClient) SupplyBody(buffer: ref NetBuffer) -> Result<Unit,HttpsClientError> {
  if self.cell==nil { return HttpsClientError{protocol_error:HttpError{kind:HttpErrorKind.Closed}}; }
  let s: arc<HttpsData> = self.cell as arc<HttpsData>; let control: HttpsClientError? = https_stream_control(s); if control!=nil { return control as HttpsClientError; }
  let result: Result<Unit,HttpError> = s.exchange.SupplyBody(buffer);
  if result.IsErr() { return https_protocol(s,(result.get_if<HttpError>()) as HttpError); } return Unit{};
}
/** @brief Close the drained producer; terminal framing errors retire both transport and engine. */
pub method(HttpsClient) FinishBody(trailers: ref <HttpField>[]) -> Result<Unit,HttpsClientError> {
  if self.cell==nil { return HttpsClientError{protocol_error:HttpError{kind:HttpErrorKind.Closed}}; }
  let s: arc<HttpsData> = self.cell as arc<HttpsData>; let control: HttpsClientError? = https_stream_control(s); if control!=nil { return control as HttpsClientError; }
  let result: Result<Unit,HttpError> = s.exchange.FinishBody(trailers);
  if result.IsErr() {
    let error: HttpsClientError = https_protocol(s,(result.get_if<HttpError>()) as HttpError);
    if s.streaming && s.exchange.UploadState().IsErr() { return https_fail(s,error); } return error;
  }
  return Unit{};
}
func https_stream_shutdown(s: arc<HttpsData>) -> Result<Unit,HttpsClientError> {
  let state: Result<HttpUploadState,HttpError> = s.exchange.UploadState();
  if state.IsErr() { return https_fail(s,https_protocol(s,(state.get_if<HttpError>()) as HttpError)); }
  // Never flush accepted-but-unsent upload records solely to send close_notify.
  if ((state.get_if<HttpUploadState>()) as HttpUploadState)==HttpUploadState.Stopped { let ignored: HttpsClientError = https_fail(s,https_protocol(s,HttpError{kind:HttpErrorKind.Closed})); return Unit{}; }
  while true {
    let flushed: Result<bool,TlsStreamError> = s.channel.Flush(s.options);
    if flushed.IsErr() { return https_fail(s,https_provider(s,(flushed.get_if<TlsStreamError>()) as TlsStreamError)); }
    if (flushed.get_if<bool>()) as bool { break; }
    let waited: HttpsClientError? = https_stream_wait(s,false,true,false); if waited!=nil { return waited as HttpsClientError; }
  }
  let closed: Result<Unit,TlsStreamError> = s.channel.Shutdown(s.options);
  if closed.IsErr() { return https_fail(s,https_provider(s,(closed.get_if<TlsStreamError>()) as TlsStreamError)); }
  let retired: HttpsClientError = https_fail(s,https_protocol(s,HttpError{kind:HttpErrorKind.Closed}));
  return Unit{};
}
