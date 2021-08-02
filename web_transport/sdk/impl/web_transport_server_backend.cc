/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "impl/web_transport_server_backend.h"
#include "impl/web_transport_server_session.h"

namespace owt {
namespace quic {

WebTransportServerBackend::WebTransportServerBackend(
    base::SingleThreadTaskRunner* io_runner,
    base::SingleThreadTaskRunner* event_runner)
    : visitor_(nullptr), io_runner_(io_runner), event_runner_(event_runner) {
  // Construction of WebTransportServerBackend is not required to be ran on IO
  // thread.
  io_thread_checker_.DetachFromThread();
  DCHECK(io_runner);
  DCHECK(event_runner);
}

WebTransportServerBackend::~WebTransportServerBackend() {}

void WebTransportServerBackend::SetVisitor(
    WebTransportServerInterface::Visitor* visitor) {
  visitor_ = visitor;
}

void WebTransportServerBackend::OnSessionReady(
    ::quic::WebTransportHttp3* session,
    ::quic::QuicSpdySession* http3_session) {
  // This method is expected to be called on IO thread(io_runner_).
  DCHECK(io_thread_checker_.CalledOnValidThread());
  LOG(INFO) << "On session ready " << session->id();
  std::unique_ptr<WebTransportServerSession> wt_session =
      std::make_unique<WebTransportServerSession>(session, http3_session,
                                                  io_runner_, event_runner_);
  WebTransportServerSession* session_ptr = wt_session.get();
  if (sessions_.count(http3_session->connection_id().ToString()) > 0) {
    LOG(WARNING) << "Session with the same connection ID exits, the old one "
                    "will be terminated. Only one WebTransport session for a "
                    "QUIC connection is supported.";
  }
  sessions_[http3_session->connection_id().ToString()] = std::move(wt_session);
  if (visitor_) {
    visitor_->OnSession(session_ptr);
  } else {
    LOG(INFO) << "No visitor for backend.";
  }
}

}  // namespace quic
}  // namespace owt