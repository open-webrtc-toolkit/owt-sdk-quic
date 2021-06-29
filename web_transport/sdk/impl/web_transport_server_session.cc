/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Most classes in this file and its implementations are borrowed from
// Chromium/net/third_party/quiche/src/quic/tools/quic_simple_server_session.cc
// with modifications.

#include "impl/web_transport_server_session.h"
#include <vector>
#include "impl/web_transport_stream_impl.h"
#include "net/third_party/quiche/src/quic/core/http/quic_server_initiated_spdy_stream.h"
#include "net/third_party/quiche/src/quic/core/http/quic_spdy_stream.h"

namespace owt {
namespace quic {

// Copied from net/quic/dedicated_web_transport_http3_client.cc.
class WebTransportVisitorProxy : public ::quic::WebTransportVisitor {
 public:
  explicit WebTransportVisitorProxy(::quic::WebTransportVisitor* visitor)
      : visitor_(visitor) {}

  void OnSessionReady() override { visitor_->OnSessionReady(); }
  void OnIncomingBidirectionalStreamAvailable() override {
    visitor_->OnIncomingBidirectionalStreamAvailable();
  }
  void OnIncomingUnidirectionalStreamAvailable() override {
    visitor_->OnIncomingUnidirectionalStreamAvailable();
  }
  void OnDatagramReceived(absl::string_view datagram) override {
    visitor_->OnDatagramReceived(datagram);
  }
  void OnCanCreateNewOutgoingBidirectionalStream() override {
    visitor_->OnCanCreateNewOutgoingBidirectionalStream();
  }
  void OnCanCreateNewOutgoingUnidirectionalStream() override {
    visitor_->OnCanCreateNewOutgoingUnidirectionalStream();
  }

 private:
  ::quic::WebTransportVisitor* visitor_;
};

WebTransportServerSession::WebTransportServerSession(
    ::quic::WebTransportHttp3* session,
    base::SingleThreadTaskRunner* io_runner,
    base::SingleThreadTaskRunner* event_runner)
    : session_(session),
      io_runner_(io_runner),
      event_runner_(event_runner),
      visitor_(nullptr) {
  CHECK(session_);
  CHECK(io_runner_);
  CHECK(event_runner_);
  session_->SetVisitor(std::make_unique<WebTransportVisitorProxy>(this));
}

WebTransportServerSession::~WebTransportServerSession() {}

WebTransportStreamInterface*
WebTransportServerSession::CreateBidirectionalStream() {
  std::unique_ptr<WebTransportStreamInterface> stream =
      std::make_unique<WebTransportStreamImpl>(
          session_->OpenOutgoingBidirectionalStream(), io_runner_,
          event_runner_);
  WebTransportStreamInterface* stream_ptr(stream.get());
  streams_.push_back(std::move(stream));
  return stream_ptr;
}

uint64_t WebTransportServerSession::SessionId() const {
  return session_->id();
}

const char* WebTransportServerSession::ConnectionId() const {
  const std::string& session_id_str = std::to_string(SessionId());
  char* id = new char[session_id_str.size() + 1];
  strcpy(id, session_id_str.c_str());
  return id;
}

bool WebTransportServerSession::IsSessionReady() const {
  // A WebTransport session is created after a QUIC session is ready.
  return true;
}

void WebTransportServerSession::SetVisitor(
    WebTransportSessionInterface::Visitor* visitor) {
  visitor_ = visitor;
}

const ConnectionStats& WebTransportServerSession::GetStats() {
  return stats_;
}

void WebTransportServerSession::OnIncomingBidirectionalStreamAvailable() {
  auto* stream = session_->AcceptIncomingBidirectionalStream();
  AcceptIncomingStream(stream);
}

void WebTransportServerSession::OnIncomingUnidirectionalStreamAvailable() {
  auto* stream = session_->AcceptIncomingUnidirectionalStream();
  AcceptIncomingStream(stream);
}

void WebTransportServerSession::AcceptIncomingStream(
    ::quic::WebTransportStream* stream) {
  LOG(INFO) << "Accept incoming stream.";
  std::unique_ptr<WebTransportStreamInterface> wt_stream =
      std::make_unique<WebTransportStreamImpl>(stream, io_runner_,
                                               event_runner_);
  WebTransportStreamInterface* stream_ptr = wt_stream.get();
  streams_.push_back(std::move(wt_stream));
  if (visitor_) {
    visitor_->OnIncomingStream(stream_ptr);
  }
}

}  // namespace quic
}  // namespace owt