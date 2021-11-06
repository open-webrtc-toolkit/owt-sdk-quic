/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_WEB_TRANSPORT_WEB_TRANSPORT_SERVER_BACKEND_H_
#define OWT_QUIC_WEB_TRANSPORT_WEB_TRANSPORT_SERVER_BACKEND_H_

#include "base/threading/thread_checker.h"
#include "impl/web_transport_server_session.h"
#include "net/third_party/quiche/src/quic/core/http/web_transport_http3.h"
#include "net/third_party/quiche/src/quic/core/web_transport_interface.h"
#include "owt/quic/web_transport_server_interface.h"

namespace owt {
namespace quic {

class WebTransportSessionVisitor {
 public:
  virtual ~WebTransportSessionVisitor() {}
  WebTransportServerBackend& operator=(WebTransportServerBackend&) = delete;
  virtual void OnSessionReady(::quic::WebTransportHttp3* session,
                              ::quic::QuicSpdySession* http3_session) = 0;
  virtual void OnSessionClosed(::quic::WebTransportSessionId id) = 0;
};

// Handle WebTransport requests and responses.
class WebTransportServerBackend : public WebTransportSessionVisitor {
 public:
  explicit WebTransportServerBackend(
      base::SingleThreadTaskRunner* io_runner,
      base::SingleThreadTaskRunner* event_runner);
  ~WebTransportServerBackend() override;

  void SetVisitor(WebTransportServerInterface::Visitor* visitor);

  // Overrides WebTransportSessionVisitor.
  void OnSessionReady(::quic::WebTransportHttp3* session,
                      ::quic::QuicSpdySession* http3_session) override;
  void OnSessionClosed(::quic::WebTransportSessionId id) override {}

 private:
  WebTransportServerInterface::Visitor* visitor_;
  // Key is HTTP/3 QUIC stream connection ID.
  std::unordered_map<std::string, std::unique_ptr<WebTransportServerSession>>
      sessions_;
  base::SingleThreadTaskRunner* io_runner_;
  base::SingleThreadTaskRunner* event_runner_;
  base::ThreadChecker io_thread_checker_;
};
}  // namespace quic
}  // namespace owt

#endif