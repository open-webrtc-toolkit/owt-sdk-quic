/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_TRANSPORT_ICE_TRANSPORT_INTERFACE_H_
#define OWT_QUIC_TRANSPORT_ICE_TRANSPORT_INTERFACE_H_

namespace owt {
namespace quic {
/**
@brief Interface for ICE transport.
*/
class IceTransportInterface {
 public:
  /// Write packet to underlying transport.
  virtual int SendPacket(const char* data, int length) = 0;
};
}  // namespace quic
}  // namespace owt

#endif