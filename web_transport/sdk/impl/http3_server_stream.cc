/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "impl/http3_server_stream.h"

namespace owt {
namespace quic {

Http3ServerStream::Http3ServerStream(::quic::QuicStreamId id,
                                     ::quic::QuicSpdySession* session,
                                     ::quic::StreamType type,
                                     base::SingleThreadTaskRunner* io_runner,
                                     base::SingleThreadTaskRunner* event_runner)
    : QuicSpdyServerStreamBase(id, session, type),
      io_runner_(io_runner),
      event_runner_(event_runner) {
  DCHECK(io_runner_);
  DCHECK(event_runner_);
}

Http3ServerStream::Http3ServerStream(::quic::PendingStream* pending,
                                     ::quic::QuicSpdySession* session,
                                     ::quic::StreamType type,
                                     base::SingleThreadTaskRunner* io_runner,
                                     base::SingleThreadTaskRunner* event_runner)
    : QuicSpdyServerStreamBase(pending, session, type),
      io_runner_(io_runner),
      event_runner_(event_runner) {
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

}  // namespace quic
}  // namespace owt