/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_TRANSPORT_STREAM_INTERFACE_H_
#define OWT_QUIC_TRANSPORT_STREAM_INTERFACE_H_

#include "owt/quic/export.h"
#include "stddef.h"
#include "stdint.h"

namespace quic {
class OWT_EXPORT QuicTransportStreamInterface {
 public:
  class Visitor {
   public:
    virtual ~Visitor() = default;
    // Called when new data is available.
    virtual void OnData(QuicTransportStreamInterface* stream, char* data, size_t len) = 0;
  };
  virtual ~QuicTransportStreamInterface() = default;
  // QUIC stream ID.
  virtual uint32_t Id() const = 0;
  virtual void SetVisitor(Visitor* visitor) = 0;
  virtual void SendData(char* data, size_t len) = 0;
};
}  // namespace quic

#endif