/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_WEB_TRANSPORT_TESTS_WEB_TRANSPORT_ECHO_VISITORS_H_
#define OWT_QUIC_WEB_TRANSPORT_TESTS_WEB_TRANSPORT_ECHO_VISITORS_H_

#include <memory>
#include <vector>
#include "owt/quic/web_transport_client_interface.h"
#include "owt/quic/web_transport_server_interface.h"

namespace owt {
namespace quic {
namespace test {

class StreamEchoVisitor : public WebTransportStreamInterface::Visitor {
 public:
  explicit StreamEchoVisitor(WebTransportStreamInterface* stream);
  void OnCanWrite() override {}
  void OnCanRead() override;
  void OnFinRead() override {}

 private:
  WebTransportStreamInterface* stream_;
};

class SessionEchoVisitor : public WebTransportSessionInterface::Visitor {
 public:
  explicit SessionEchoVisitor();
  ~SessionEchoVisitor() override;

  void OnCanCreateNewOutgoingStream(bool) override {}
  void OnConnectionClosed() override {}
  void OnIncomingStream(WebTransportStreamInterface* stream) override;
  void OnDatagramReceived(const uint8_t* data, size_t length) override {}

 private:
  std::vector<std::unique_ptr<StreamEchoVisitor>> stream_visitors_;
};

class ServerEchoVisitor : public WebTransportServerInterface::Visitor {
 public:
  explicit ServerEchoVisitor();
  ~ServerEchoVisitor() override;

  void OnEnded() override {}
  void OnSession(WebTransportSessionInterface* session) override;

  std::vector<WebTransportSessionInterface*> Sessions() const {
    return sessions_;
  }

 private:
  std::vector<std::unique_ptr<SessionEchoVisitor>> session_visitors_;
  // A list of sessions created in the order of their creation. Closed sessions
  // are not removed.
  std::vector<WebTransportSessionInterface*> sessions_;
};

}  // namespace test
}  // namespace quic
}  // namespace owt

#endif