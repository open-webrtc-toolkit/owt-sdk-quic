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

#include "base/single_thread_task_runner.h"
#include "impl/http3_server_session.h"
#include "net/third_party/quiche/src/quic/core/http/web_transport_http3.h"
#include "owt/quic/web_transport_session_interface.h"

namespace owt {
namespace quic {

// A proxy of ::quic::WebTransportHttp3. WebTransport over HTTP/2 is not
// supported.
class WebTransportServerSession : public WebTransportSessionInterface {
 public:
  explicit WebTransportServerSession(
      ::quic::WebTransportHttp3* session,
      base::SingleThreadTaskRunner* io_runner,
      base::SingleThreadTaskRunner* event_runner);
  ~WebTransportServerSession() override;

  // Override QuicTransportSessionInterface.
  const char* ConnectionId() const override;
  void SetVisitor(WebTransportSessionInterface::Visitor* visitor) override;
  bool IsSessionReady() const override;
  WebTransportStreamInterface* CreateBidirectionalStream() override;
  const ConnectionStats& GetStats() override;

 private:
  ::quic::WebTransportHttp3* session_;
  base::SingleThreadTaskRunner* io_runner_;
  base::SingleThreadTaskRunner* event_runner_;
  std::vector<std::unique_ptr<WebTransportStreamInterface>> streams_;
};
}  // namespace quic
}  // namespace owt

#endif