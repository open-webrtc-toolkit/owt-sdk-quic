/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "impl/http3_server_stream.h"
#include "impl/web_transport_server_backend.h"
#include "net/third_party/quiche/src/quic/core/http/spdy_utils.h"
#include "net/third_party/quiche/src/quic/core/http/web_transport_http3.h"

namespace owt {
namespace quic {

Http3ServerStream::Http3ServerStream(::quic::QuicStreamId id,
                                     ::quic::QuicSpdySession* session,
                                     ::quic::StreamType type,
                                     WebTransportServerBackend* backend,
                                     base::SingleThreadTaskRunner* io_runner,
                                     base::SingleThreadTaskRunner* event_runner)
    : QuicSpdyServerStreamBase(id, session, type),
      backend_(backend),
      io_runner_(io_runner),
      event_runner_(event_runner) {
  DCHECK(backend_);
  DCHECK(io_runner_);
  DCHECK(event_runner_);
}

Http3ServerStream::Http3ServerStream(::quic::PendingStream* pending,
                                     ::quic::QuicSpdySession* session,
                                     WebTransportServerBackend* backend,
                                     base::SingleThreadTaskRunner* io_runner,
                                     base::SingleThreadTaskRunner* event_runner)
    : QuicSpdyServerStreamBase(pending, session),
      backend_(backend),
      io_runner_(io_runner),
      event_runner_(event_runner),
      content_length_(0) {
  DCHECK(backend_);
  DCHECK(io_runner_);
  DCHECK(event_runner_);
}

void Http3ServerStream::OnBodyAvailable() {
  // Since this server is designed for WebTransport only, it only accepts
  // CONNECT requests. As per
  // https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.6, A payload
  // within a CONNECT request message has no defined semantics.
  LOG(WARNING) << "Body is not expected.";
}

void Http3ServerStream::OnInitialHeadersComplete(
    bool fin,
    size_t frame_len,
    const ::quic::QuicHeaderList& header_list) {
  QuicSpdyServerStreamBase::OnInitialHeadersComplete(fin, frame_len,
                                                     header_list);
  if (!::quic::SpdyUtils::CopyAndValidateHeaders(header_list, &content_length_,
                                                 &request_headers_)) {
    DVLOG(1) << "Invalid headers";
    SendErrorResponse(400);
  }
  ConsumeHeaderList();
  auto it = request_headers_.find(":method");
  if (it == request_headers_.end() ||
      !absl::StartsWith(it->second, "CONNECT")) {
    // Only support CONNECT for WebTransport.
    SendErrorResponse(405);
  }
  SendResponse();
}

void Http3ServerStream::SendResponse() {
  if (!web_transport()) {
    LOG(WARNING) << "Cannot find WebTransport session.";
    return SendErrorResponse(500);
  }
  backend_->OnSessionReady(web_transport(), spdy_session());
  spdy::Http2HeaderBlock response_headers;
  response_headers[":status"] = "200";
  WriteHeaders(std::move(response_headers), false, nullptr);
  web_transport()->HeadersReceived(request_headers_);
}

void Http3ServerStream::SendErrorResponse(int resp_code) {
  spdy::Http2HeaderBlock headers;
  headers[":status"] = absl::StrCat(resp_code);
  std::string error_body("Error.");
  headers["content-length"] = absl::StrCat(strlen(error_body.c_str()));
  WriteHeaders(std::move(headers), false, nullptr);
  WriteOrBufferBody(error_body, true);
}

}  // namespace quic
}  // namespace owt