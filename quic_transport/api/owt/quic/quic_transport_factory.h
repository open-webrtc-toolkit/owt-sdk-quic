/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_TRANSPORT_QUIC_TRANSPORT_FACTORY_H_
#define OWT_QUIC_TRANSPORT_QUIC_TRANSPORT_FACTORY_H_

#include "owt/quic/export.h"

namespace owt {
namespace quic {

class P2PQuicTransportInterface;
class P2PQuicPacketTransportInterface;
class QuicTransportServerInterface;

class OWT_EXPORT QuicTransportFactory {
 public:
  virtual ~QuicTransportFactory() = default;

  /// Create a QuicTransportFactory.
  static QuicTransportFactory* Create();
  // `accepted_origins` is removed at this time because ABI compatible issue.
  // Ownership of returned value is moved to caller.
  virtual QuicTransportServerInterface* CreateQuicTransportServer(
      int port,
      const char* cert_path,
      const char* key_path,
      const char*
          secret_path /*, std::vector<std::string> accepted_origins*/) = 0;
  virtual void ReleaseQuicTransportServer(
      const QuicTransportServerInterface* server) = 0;
};
}  // namespace quic
}  // namespace owt

#endif