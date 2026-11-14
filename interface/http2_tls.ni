// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "tls:tls.ny";
import "http:http.ny";
import "http:http2.ny";

/** @brief Failure during URL admission, connection or verified TLS negotiation. */
pub struct SecureHttp2Error {
  protocol: Http2Error?;
  tls: TlsStreamError?;
}

/** @brief Open a verified HTTPS connection which negotiates exactly h2.
 * @param ca_file Required PEM trust file. The URL determines the verified identity.
 * @param provider_file Trusted path to the native HTTP/2 bridge shared library.
 * @note Use the same deadline and token for subsequent Receive calls if the
 * entire exchange must share one control budget. */
pub static method(Http2Client) OpenSecure(
  url: ref HttpUrl, ca_file: ref string, provider_file: ref string, resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions, limits: ref Http2Limits, options: ref NetOperationOptions
) -> Result<Http2Client, SecureHttp2Error>;
