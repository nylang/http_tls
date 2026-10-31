// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/**
 * @brief Streamed HTTPS scheduling over the optional TLS channel; shared HTTP grammar and
 *   producers.
 */
part of HttpsClientAdapter;

method(HttpsData) ControlError() -> HttpsClientError? {
  if self.failure != nil {
    return self.failure;
  }

  let result: Result<Unit, NetError> = self.options.CheckNow();
  if result.IsErr() {
    return self.Fail(self.ProviderError(TlsStreamError{transport_error: (result.get_if<NetError>()) as NetError}));
  }

  return nil;
}

/**
 * @brief Validate a streamed head and adopt TCP into the optional caller-thread TLS channel.
 * @param continue_wait_ms Finite 0..60000 ms fallback, started once after head ciphertext flush.
 * @returns Ok with HttpsClient on success; Err with HttpsClientError on the failure paths
 *   described above.
 * @note Explicit trust, Host/peer and ALPN checks match New. The TLS channel uses 65536-byte
 *   BIOs by default; explicit capacity must be at least 32768. Existing TlsStream is unchanged.
 *   Original controls cover handshake, producer time, continue wait and all I/O. No replay/retry.
 */
pub static method(HttpsClient) NewStreaming(
  connection: ref mut TcpConnection,
  config: ref TlsClientConfig,
  head: ref NetBuffer,
  limits: ref HttpClientLimits,
  options: ref NetOperationOptions,
  continue_wait_ms: int32
) -> Result<HttpsClient, HttpsClientError> {
  let control: Result<Unit, NetError> = options.CheckNow();
  if control.IsErr() {
    return HttpsClientError{tls_error: TlsStreamError{transport_error: (control.get_if<NetError>()) as NetError}};
  }

  if continue_wait_ms<0 || continue_wait_ms>60000 {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}};
  }

  var core: Result<HttpClientExchange, HttpError> = HttpClientExchange.NewStreaming(head, limits);
  if core.IsErr() {
    return HttpsClientError{protocol_error:(core.get_if<HttpError>()) as HttpError};
  }

  var exchange: HttpClientExchange = move((core.get_if<HttpClientExchange>()) as HttpClientExchange);
  let host: string = (exchange.AuthorityHost().get_if<string>()) as string;
  if !HttpsPeerIdentity{host: host}.Matches(config.peer_name) {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}};
  }

  if config.alpn.length != 0 && !config.alpn.Equal("http/1.1") {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.Unsupported}};
  }

  var settings: TlsClientConfig = config;
  settings.alpn = "http/1.1";
  var channel: Result<TlsChannel, TlsStreamError> = TlsChannel.NewClient(connection, settings);
  if channel.IsErr() {
    return HttpsClientError{tls_error:(channel.get_if<TlsStreamError>()) as TlsStreamError};
  }

  return HttpsClient{cell: new arc<HttpsData>{
    channel: move((channel.get_if<TlsChannel>()) as TlsChannel),
    exchange: move(exchange),
    options: options,
    streaming: true,
    continue_wait_ms: continue_wait_ms
  }};
}

method(HttpsData) WaitForDirection(readable: bool, writable: bool, gate: bool) -> HttpsClientError? {
  var maximum: int32 = -1;
  if gate {
    maximum = self.continue_deadline.PollMilliseconds(Instant.Now().ToDurationSinceEpochish().ToNanoseconds());
  }

  let waited: Result<Unit, TlsStreamError> = self.channel.Wait(readable, writable, maximum, self.options);
  if waited.IsErr() {
    return self.Fail(self.ProviderError((waited.get_if<TlsStreamError>()) as TlsStreamError));
  }

  return nil;
}

// Read response progress before continuing upload output, while preserving the TLS provider retry barriers.
method(HttpsData) NextStreamEvent() -> Result<HttpClientEvent, HttpsClientError> {
  while true {
    let control: HttpsClientError? = self.ControlError();
    if control != nil {
      return control as HttpsClientError;
    }

    if !self.handshaken {
      let ready: Result<Unit, TlsStreamError> = self.channel.Handshake(self.options);
      if ready.IsErr() {
        return self.Fail(self.ProviderError((ready.get_if<TlsStreamError>()) as TlsStreamError));
      }

      let selected: Result<string, TlsStreamError> = self.channel.SelectedAlpn();
      if selected.IsErr() {
        return self.Fail(self.ProviderError((selected.get_if<TlsStreamError>()) as TlsStreamError));
      }

      let value: string = (selected.get_if<string>()) as string;
      if value.length != 0 && !value.Equal("http/1.1") {
        return self.Fail(self.ProtocolError(HttpError{kind: HttpErrorKind.Unsupported}));
      }

      self.handshaken = true;
      continue;
    }

    let queried: Result<HttpUploadState, HttpError> = self.exchange.UploadState();
    if queried.IsErr() {
      return self.Fail(self.ProtocolError((queried.get_if<HttpError>()) as HttpError));
    }

    var upload: HttpUploadState = (queried.get_if<HttpUploadState>()) as HttpUploadState;
    var provider_write_retry: bool = false;
    if upload != HttpUploadState.SendingHead {
      let advanced: Result<HttpClientEvent, HttpError> = self.exchange.NextResponse();
      if advanced.IsErr() {
        return self.Fail(self.ProtocolError((advanced.get_if<HttpError>()) as HttpError));
      }

      let event: HttpClientEvent = (advanced.get_if<HttpClientEvent>()) as HttpClientEvent;
      if event.kind != HttpClientEventKind.NeedInput {
        let checked: HttpsClientError? = self.ControlError();
        if checked != nil {
          return checked as HttpsClientError;
        }

        self.published_complete = event.complete;

        return event;
      }

      let result: Result<TlsChannelRead, TlsStreamError> = self.channel.ReadAvailable(self.options);
      if result.IsErr() {
        return self.Fail(self.ProviderError((result.get_if<TlsStreamError>()) as TlsStreamError));
      }

      let read: TlsChannelRead = (result.get_if<TlsChannelRead>()) as TlsChannelRead;
      if read.transfer.error != nil {
        var failure: HttpsClientError = self.ProviderError(read.transfer.error as TlsStreamError);
        failure.stats.response_bytes_received = failure.stats.response_bytes_received + (
          read.transfer.bytes_transferred as uint64
        );

        return self.Fail(failure);
      }

      if read.state == TlsChannelReadState.Again {
        continue;
      }

      if read.state == TlsChannelReadState.Ready {
        if read.transfer.bytes_transferred != read.transfer.buffer.Len()
          || (read.transfer.bytes_transferred == (0ip) && !read.transfer.eof) {
          return self.Fail(self.ProtocolError(HttpError{kind: HttpErrorKind.InvalidState}));
        }

        let received: Result<Unit, HttpError> = self.exchange.Receive(read.transfer.buffer, read.transfer.eof);
        if received.IsErr() {
          return self.Fail(self.ProtocolError((received.get_if<HttpError>()) as HttpError));
        }

        continue;
      }

      if read.state == TlsChannelReadState.NeedWrite {
        let waited: HttpsClientError? = self.WaitForDirection(false, true, false);
        if waited != nil {
          return waited as HttpsClientError;
        }

        continue;
      }

      provider_write_retry = read.state == TlsChannelReadState.RetryWrite;
      upload = (self.exchange.UploadState().get_if<HttpUploadState>()) as HttpUploadState;
      if read.state != TlsChannelReadState.RetryWrite {
        if upload == HttpUploadState.ReadingResponse || upload == HttpUploadState.Stopped {
          let waited: HttpsClientError? = self.WaitForDirection(true, false, false);
          if waited != nil {
            return waited as HttpsClientError;
          }

          continue;
        }

        // Flush a previously accepted block before asking for more producer data
        // or waiting for a response. Always probe responses again after blocking.
        if upload != HttpUploadState.SendingBody {
          let flushed: Result<bool, TlsStreamError> = self.channel.Flush(self.options);
          if flushed.IsErr() {
            return self.Fail(self.ProviderError((flushed.get_if<TlsStreamError>()) as TlsStreamError));
          }

          if ! ((flushed.get_if<bool>()) as bool) {
            let waited: HttpsClientError? = self.WaitForDirection(true, true, false);
            if waited != nil {
              return waited as HttpsClientError;
            }

            continue;
          }

          self.head_flushed = true;
        }

        if !self.continue_started && self.head_flushed {
          self.continue_started = true;
          self.continue_deadline = NetDeadline.After(
            Instant.Now().ToDurationSinceEpochish().ToNanoseconds(),
            (self.continue_wait_ms as uint64) * 1000000u64
          );
        }

        if upload == HttpUploadState.WaitingContinue {
          if self.continue_deadline.IsExpired(Instant.Now().ToDurationSinceEpochish().ToNanoseconds()) {
            let released: Result<Unit, HttpError> = self.exchange.ContinueUpload();
            if released.IsErr() {
              return self.Fail(self.ProtocolError((released.get_if<HttpError>()) as HttpError));
            }

            continue;
          }

          let waited: HttpsClientError? = self.WaitForDirection(true, false, true);
          if waited != nil {
            return waited as HttpsClientError;
          }

          continue;
        }

        if upload == HttpUploadState.NeedBody {
          let checked: HttpsClientError? = self.ControlError();
          if checked != nil {
            return checked as HttpsClientError;
          }

          return HttpClientEvent{kind: HttpClientEventKind.NeedBody, stats: self.exchange.Stats()};
        }

        if upload == HttpUploadState.Finished {
          let waited: HttpsClientError? = self.WaitForDirection(true, false, false);
          if waited != nil {
            return waited as HttpsClientError;
          }

          continue;
        }
      }
    }

    let output: Result<NetBuffer, HttpError> = self.exchange.Output();
    if output.IsErr() {
      return self.Fail(self.ProtocolError((output.get_if<HttpError>()) as HttpError));
    }

    let block: NetBuffer = (output.get_if<NetBuffer>()) as NetBuffer;
    if block.Len() == (0ip) {
      let next: HttpUploadState = (self.exchange.UploadState().get_if<HttpUploadState>()) as HttpUploadState;
      if next != upload {
        continue;
      }

      return self.Fail(self.ProtocolError(HttpError{kind: HttpErrorKind.InvalidState}));
    }

    let sent: Result<TlsChannelWrite, TlsStreamError> = self.channel.WriteAvailable(block, self.options);
    if sent.IsErr() {
      return self.Fail(self.ProviderError((sent.get_if<TlsStreamError>()) as TlsStreamError));
    }

    let write: TlsChannelWrite = (sent.get_if<TlsChannelWrite>()) as TlsChannelWrite;
    let acknowledged: Result<Unit, HttpError> = self.exchange.AcknowledgeOutput(
      write.transfer.bytes_transferred
    );
    if acknowledged.IsErr() {
      return self.Fail(self.ProtocolError((acknowledged.get_if<HttpError>()) as HttpError));
    }

    if write.transfer.error != nil {
      return self.Fail(self.ProviderError(write.transfer.error as TlsStreamError));
    }

    if write.transfer.bytes_transferred>(0ip) {
      continue;
    }

    if write.state == TlsChannelWriteState.RetryRead {
      continue;
    }

    let waited: HttpsClientError? = self.WaitForDirection(write.state == TlsChannelWriteState.NeedRead
        || (upload != HttpUploadState.SendingHead && !provider_write_retry),
      write.state != TlsChannelWriteState.NeedRead,
      false);
    if waited != nil {
      return waited as HttpsClientError;
    }
  }

  return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidState}};
}

/**
 * @brief Streamed producer state, or immutable/default/terminal failure without I/O.
 * @returns Ok with HttpUploadState on success; Err with HttpsClientError on the failure paths
 *   described above.
 */
pub method(HttpsClient) UploadState() -> Result<HttpUploadState, HttpsClientError> {
  if self.cell == nil {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.Closed}};
  }

  let s: arc<HttpsData> = self.cell as arc<HttpsData>;
  if s.failure != nil {
    return s.failure as HttpsClientError;
  }

  let result: Result<HttpUploadState, HttpError> = s.exchange.UploadState();
  if result.IsErr() {
    return (s).ProtocolError((result.get_if<HttpError>()) as HttpError);
  }

  return (result.get_if<HttpUploadState>()) as HttpUploadState;
}

/**
 * @brief Admit one bounded immutable body owner after NeedBody; rejected admission is
 *   nonterminal.
 * @returns Ok with Unit on success; Err with HttpsClientError on the failure paths described
 *   above.
 */
pub method(HttpsClient) SupplyBody(buffer: ref NetBuffer) -> Result<Unit, HttpsClientError> {
  if self.cell == nil {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.Closed}};
  }

  let s: arc<HttpsData> = self.cell as arc<HttpsData>;
  let control: HttpsClientError? = (s).ControlError();
  if control != nil {
    return control as HttpsClientError;
  }

  let result: Result<Unit, HttpError> = s.exchange.SupplyBody(buffer);
  if result.IsErr() {
    return (s).ProtocolError((result.get_if<HttpError>()) as HttpError);
  }

  return Unit{};
}

/**
 * @brief Finish a drained producer and validate final framing/trailers; shortages retire
 *   TCP/TLS.
 * @returns Ok with Unit on success; Err with HttpsClientError on the failure paths described
 *   above.
 */
pub method(HttpsClient) FinishBody(trailers: ref <HttpField>[]) -> Result<Unit, HttpsClientError> {
  if self.cell == nil {
    return HttpsClientError{protocol_error: HttpError{kind: HttpErrorKind.Closed}};
  }

  let s: arc<HttpsData> = self.cell as arc<HttpsData>;
  let control: HttpsClientError? = (s).ControlError();
  if control != nil {
    return control as HttpsClientError;
  }

  let result: Result<Unit, HttpError> = s.exchange.FinishBody(trailers);
  if result.IsErr() {
    let error: HttpsClientError = (s).ProtocolError((result.get_if<HttpError>()) as HttpError);
    if s.streaming && s.exchange.UploadState().IsErr() {
      return (s).Fail(error);
    }

    return error;
  }

  return Unit{};
}

// Stop an unfinished streamed upload without flushing its remaining plaintext as part of graceful shutdown.
method(HttpsData) ShutdownStream() -> Result<Unit, HttpsClientError> {
  let state: Result<HttpUploadState, HttpError> = self.exchange.UploadState();
  if state.IsErr() {
    return self.Fail(self.ProtocolError((state.get_if<HttpError>()) as HttpError));
  }

  // Never flush accepted-but-unsent upload records solely to send close_notify.
  if ((state.get_if<HttpUploadState>()) as HttpUploadState) == HttpUploadState.Stopped {
    let ignored: HttpsClientError = self.Fail(self.ProtocolError(HttpError{kind: HttpErrorKind.Closed}));

    return Unit{};
  }

  while true {
    let flushed: Result<bool, TlsStreamError> = self.channel.Flush(self.options);
    if flushed.IsErr() {
      return self.Fail(self.ProviderError((flushed.get_if<TlsStreamError>()) as TlsStreamError));
    }

    if (flushed.get_if<bool>()) as bool {
      break;
    }

    let waited: HttpsClientError? = self.WaitForDirection(false, true, false);
    if waited != nil {
      return waited as HttpsClientError;
    }
  }

  let closed: Result<Unit, TlsStreamError> = self.channel.Shutdown(self.options);
  if closed.IsErr() {
    return self.Fail(self.ProviderError((closed.get_if<TlsStreamError>()) as TlsStreamError));
  }

  let retired: HttpsClientError = self.Fail(self.ProtocolError(HttpError{kind: HttpErrorKind.Closed}));

  return Unit{};
}
