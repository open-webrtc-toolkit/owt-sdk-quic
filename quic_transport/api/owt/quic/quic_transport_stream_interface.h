/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_QUIC_TRANSPORT_STREAM_INTERFACE_H_
#define OWT_QUIC_QUIC_TRANSPORT_STREAM_INTERFACE_H_

#include "owt/quic/export.h"

namespace owt {
namespace quic {
class OWT_EXPORT QuicTransportStreamInterface {
 public:
  class Visitor {
   public:
    virtual ~Visitor() = default;
    // Called when new data is available.
    virtual void OnCanRead() = 0;
    // Called when stream is ready to write.
    virtual void OnCanWrite() = 0;
  };
  virtual ~QuicTransportStreamInterface() = default;
  virtual void SetVisitor(Visitor* visitor) = 0;
};
}  // namespace quic
}  // namespace owt

#endif