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
  DCHECK(io_runner);
  DCHECK(event_runner);
}

WebTransportServerBackend::~WebTransportServerBackend() {}

void WebTransportServerBackend::SetVisitor(
    WebTransportServerInterface::Visitor* visitor) {
  visitor_ = visitor;
}

void WebTransportServerBackend::OnSessionReady(
    ::quic::WebTransportHttp3* session) {
  LOG(INFO) << "On session ready " << session->id();
  std::unique_ptr<WebTransportServerSession> wt_session =
      std::make_unique<WebTransportServerSession>(session, io_runner_,
                                                  event_runner_);
  sessions_[session->id()] = std::move(wt_session);
  if (visitor_) {
    visitor_->OnSession(sessions_[session->id()].get());
  } else {
    LOG(INFO) << "No visitor for backend.";
  }
}

}  // namespace quic
}  // namespace owt