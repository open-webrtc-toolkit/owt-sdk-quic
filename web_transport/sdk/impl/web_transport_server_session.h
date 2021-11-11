/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OWT_QUIC_WEB_TRANSPORT_WEB_TRANSPORT_SERVER_SESSION_H_
#define OWT_QUIC_WEB_TRANSPORT_WEB_TRANSPORT_SERVER_SESSION_H_

#include "base/task/single_thread_task_runner.h"
#include "impl/http3_server_session.h"
#include "net/third_party/quiche/src/quic/core/http/web_transport_http3.h"
#include "owt/quic/web_transport_session_interface.h"

namespace owt {
namespace quic {

// A proxy of ::quic::WebTransportHttp3. WebTransport over HTTP/2 is not
// supported.
class WebTransportServerSession : public WebTransportSessionInterface,
                                  public ::quic::WebTransportVisitor {
 public:
  explicit WebTransportServerSession(
      ::quic::WebTransportHttp3* session,
      ::quic::QuicSpdySession* http3_session,
      base::SingleThreadTaskRunner* io_runner,
      base::SingleThreadTaskRunner* event_runner);
  ~WebTransportServerSession() override;

  // This method is going to replace ConnectionId();
  uint64_t SessionId() const;

  // Override WebTransportSessionInterface.
  const char* ConnectionId() const override;
  void SetVisitor(WebTransportSessionInterface::Visitor* visitor) override;
  bool IsSessionReady() const override;
  WebTransportStreamInterface* CreateBidirectionalStream() override;
  MessageStatus SendOrQueueDatagram(uint8_t* data, size_t length) override;
  // TODO: This method is not implemented.
  const ConnectionStats& GetStats() override;
  void Close(uint32_t code, const char* reason) override;

  // Overrides ::quic::WebTransportVisitor.
  void OnSessionReady(const spdy::SpdyHeaderBlock& headers) override {}
  void OnSessionClosed(::quic::WebTransportSessionError error_code,
                       const std::string& error_message) override {}
  void OnIncomingBidirectionalStreamAvailable() override;
  void OnIncomingUnidirectionalStreamAvailable() override;
  void OnDatagramReceived(absl::string_view datagram) override {}
  void OnCanCreateNewOutgoingUnidirectionalStream() override {}
  void OnCanCreateNewOutgoingBidirectionalStream() override {}

  void AcceptIncomingStream(::quic::WebTransportStream* stream);

 protected:
  WebTransportStreamInterface* CreateBidirectionalStreamOnCurrentThread();

 private:
  ::quic::WebTransportHttp3* session_;
  ::quic::QuicSpdySession* http3_session_;
  base::SingleThreadTaskRunner* io_runner_;
  base::SingleThreadTaskRunner* event_runner_;
  std::vector<std::unique_ptr<WebTransportStreamInterface>> streams_;
  WebTransportSessionInterface::Visitor* visitor_;
  ConnectionStats stats_;
};
}  // namespace quic
}  // namespace owt

#endif