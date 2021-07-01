/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_WEB_TRANSPORT_HTTP3_SERVER_STREAM_H_
#define OWT_QUIC_WEB_TRANSPORT_HTTP3_SERVER_STREAM_H_

#include "base/single_thread_task_runner.h"
#include "net/third_party/quiche/src/quic/core/http/quic_spdy_server_stream_base.h"

namespace owt {
namespace quic {

class WebTransportServerBackend;

class Http3ServerStream : public ::quic::QuicSpdyServerStreamBase {
 public:
  explicit Http3ServerStream(::quic::QuicStreamId id,
                             ::quic::QuicSpdySession* session,
                             ::quic::StreamType type,
                             WebTransportServerBackend* backend,
                             base::SingleThreadTaskRunner* io_runner,
                             base::SingleThreadTaskRunner* event_runner);
  explicit Http3ServerStream(::quic::PendingStream* pending,
                             ::quic::QuicSpdySession* session,
                             ::quic::StreamType type,
                             WebTransportServerBackend* backend,
                             base::SingleThreadTaskRunner* io_runner,
                             base::SingleThreadTaskRunner* event_runner);

  // Overrides QuicSpdyStream.
  void OnBodyAvailable() override;
  void OnInitialHeadersComplete(
      bool fin,
      size_t frame_len,
      const ::quic::QuicHeaderList& header_list) override;

 protected:
  // Send a 200 response to client to accept WebTransport connections.
  virtual void SendResponse();
  // Send an error response to client to reject all other requests.
  virtual void SendErrorResponse(int resp_code);

 private:
  WebTransportServerBackend* backend_;
  base::SingleThreadTaskRunner* io_runner_;
  base::SingleThreadTaskRunner* event_runner_;
  spdy::Http2HeaderBlock request_headers_;
  int64_t content_length_;
};
}  // namespace quic
}  // namespace owt

#endif