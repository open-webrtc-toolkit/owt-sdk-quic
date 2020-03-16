/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_QUIC_TRANSPORT_SERVER_INTERFACE_H_
#define OWT_QUIC_QUIC_TRANSPORT_SERVER_INTERFACE_H_

#include "export.h"

namespace owt {
namespace quic {
// A server accepts WebTransport - QuicTransport connections.
class OWT_EXPORT QuicTransportServerInterface {
 public:
  class Visitor {
    virtual ~Visitor();
    virtual void OnEnded();
  };
  virtual ~QuicTransportServerInterface() = default;
  virtual int Start() = 0;
  virtual void Stop() = 0;
  virtual void SetVisitor(Visitor* visitor) = 0;
};
}  // namespace quic
}  // namespace owt

#endif