/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_TRANSPORT_SESSION_INTERFACE_H_
#define OWT_QUIC_TRANSPORT_SESSION_INTERFACE_H_

#include "owt/quic/export.h"
#include "owt/quic/quic_transport_stream_interface.h"

namespace owt {
namespace quic {
class OWT_EXPORT QuicTransportSessionInterface {
 public:
  class Visitor {
   public:
    virtual ~Visitor() = default;
    virtual void OnIncomingStream(QuicTransportStreamInterface*) = 0;
    virtual void OnStreamClosed(uint32_t id) = 0;
  };
  virtual ~QuicTransportSessionInterface() = default;
  virtual void SetVisitor(Visitor* visitor) = 0;
  virtual void Stop() = 0;
  virtual QuicTransportStreamInterface* CreateBidirectionalStream() = 0;
  virtual const char* Id() = 0;
  virtual uint8_t length() = 0;
  virtual void CloseStream(uint32_t id) = 0;
};
}  // namespace quic
}

#endif