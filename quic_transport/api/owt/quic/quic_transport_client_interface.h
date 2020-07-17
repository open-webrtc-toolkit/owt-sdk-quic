/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_QUIC_TRANSPORT_CLIENT_INTERFACE_H_
#define OWT_QUIC_QUIC_TRANSPORT_CLIENT_INTERFACE_H_

#include "owt/quic/export.h"
#include "owt/quic/quic_definitions.h"
#include "owt/quic/quic_transport_session_interface.h"

namespace owt {
namespace quic {
// A client connects to QuicTransportServer.
class OWT_EXPORT QuicTransportClientInterface {
 public:
  // https://wicg.github.io/web-transport/#dom-quictransportconfiguration-server_certificate_fingerprints.
  struct OWT_EXPORT Parameters {
    CertificateFingerprint** server_certificate_fingerprints;
    size_t server_certificate_fingerprints_length;
  };

  class Visitor {
   public:
    virtual ~Visitor() = default;
    // Called when connected to a server.
    virtual void OnConnected() = 0;
    // Called when a connection is failed.
    virtual void OnConnectionFailed() = 0;
  };
  virtual ~QuicTransportClientInterface() = default;
  virtual void SetVisitor(Visitor* visitor) = 0;
  virtual void Connect() = 0;
};
}  // namespace quic
}  // namespace owt

#endif