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
class Http3ServerStream : public ::quic::QuicSpdyServerStreamBase {
 public:
  explicit Http3ServerStream(::quic::QuicStreamId id,
                             ::quic::QuicSpdySession* session,
                             ::quic::StreamType type,
                             base::SingleThreadTaskRunner* io_runner,
                             base::SingleThreadTaskRunner* event_runner);
  explicit Http3ServerStream(::quic::PendingStream* pending,
                             ::quic::QuicSpdySession* session,
                             ::quic::StreamType type,
                             base::SingleThreadTaskRunner* io_runner,
                             base::SingleThreadTaskRunner* event_runner);

  void OnBodyAvailable() override;

 private:
  base::SingleThreadTaskRunner* io_runner_;
  base::SingleThreadTaskRunner* event_runner_;
};
}  // namespace quic
}  // namespace owt

#endif