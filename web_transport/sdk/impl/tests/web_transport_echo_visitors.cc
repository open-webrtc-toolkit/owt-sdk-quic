/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "impl/tests/web_transport_echo_visitors.h"
#include "base/check.h"
#include "base/logging.h"

namespace owt {
namespace quic {
namespace test {

StreamEchoVisitor::StreamEchoVisitor(WebTransportStreamInterface* stream)
    : stream_(stream) {
  CHECK(stream);
}

void StreamEchoVisitor::OnCanRead() {
  auto read_size = stream_->ReadableBytes();
  if (read_size == 0) {
    return;
  }
  std::vector<uint8_t> data(read_size);
  DCHECK(data.data());
  stream_->Read(data.data(), read_size);
  stream_->Write(data.data(), read_size);
}

SessionEchoVisitor::SessionEchoVisitor() {}

SessionEchoVisitor::~SessionEchoVisitor() {}

void SessionEchoVisitor::OnIncomingStream(WebTransportStreamInterface* stream) {
  LOG(INFO) << "Session on incoming stream.";
  std::unique_ptr<StreamEchoVisitor> visitor =
      std::make_unique<StreamEchoVisitor>(stream);
  stream->SetVisitor(visitor.get());
  stream_visitors_.push_back(std::move(visitor));
}

ServerEchoVisitor::ServerEchoVisitor() {}

ServerEchoVisitor::~ServerEchoVisitor() {}

void ServerEchoVisitor::OnSession(WebTransportSessionInterface* session) {
  CHECK(session);
  std::unique_ptr<SessionEchoVisitor> visitor =
      std::make_unique<SessionEchoVisitor>();
  session->SetVisitor(visitor.get());
  session_visitors_.push_back(std::move(visitor));
  sessions_.emplace_back(session);
}

}  // namespace test
}  // namespace quic
}  // namespace owt