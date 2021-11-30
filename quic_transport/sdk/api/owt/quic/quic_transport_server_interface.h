/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_WEB_TRANSPORT_WEB_TRANSPORT_SERVER_INTERFACE_H_
#define OWT_WEB_TRANSPORT_WEB_TRANSPORT_SERVER_INTERFACE_H_

#include "owt/quic/export.h"
#include "owt/quic/quic_transport_stream_interface.h"

namespace quic {
// A server accepts WebTransport connections.
class OWT_EXPORT QuicTransportServerInterface {
 public:
  class Visitor {
   public:
    virtual ~Visitor() = default;
    // Called when server is stopped.
    virtual void OnEnded() = 0;
    // Called when a new session is created.
    virtual void OnSession(QuicTransportSessionInterface*) = 0;
  };
  virtual ~QuicTransportServerInterface() = default;
  virtual int Start() = 0;
  virtual void Stop() = 0;
  virtual void SetVisitor(Visitor* visitor) = 0;
};
}  // namespace quic

#endif