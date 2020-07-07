/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_QUIC_TRANSPORT_SESSION_INTERFACE_H_
#define OWT_QUIC_QUIC_TRANSPORT_SESSION_INTERFACE_H_

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
    virtual void OnCanCreateNewOutgoingStream(bool unidirectional) = 0;
  };
  virtual ~QuicTransportSessionInterface() = default;
  virtual const char* ConnectionId() = 0;
  virtual void SetVisitor(Visitor* visitor) = 0;
  virtual QuicTransportStreamInterface* CreateBidirectionalStream() = 0;
};
}  // namespace quic
}  // namespace owt

#endif