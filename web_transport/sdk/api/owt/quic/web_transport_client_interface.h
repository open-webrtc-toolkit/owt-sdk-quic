/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_WEB_TRANSPORT_WEB_TRANSPORT_CLIENT_INTERFACE_H_
#define OWT_WEB_TRANSPORT_WEB_TRANSPORT_CLIENT_INTERFACE_H_

#include "owt/quic/export.h"
#include "owt/quic/web_transport_definitions.h"
#include "owt/quic/web_transport_session_interface.h"

namespace owt {
namespace quic {
// A client manages a connection to a QuicTransportServer.
class OWT_EXPORT WebTransportClientInterface {
 public:
  // https://wicg.github.io/web-transport/#dom-quictransportconfiguration-server_certificate_fingerprints.
  struct OWT_EXPORT Parameters {
    Parameters() : server_certificate_fingerprints_length(0) {}
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
    // Called when an incoming stream is received.
    virtual void OnIncomingStream(WebTransportStreamInterface*) = 0;
  };
  virtual ~WebTransportClientInterface() = default;
  virtual void SetVisitor(Visitor* visitor) = 0;
  // Connect to a QUIC transport server. URL is specified during creation.
  virtual void Connect() = 0;
  // Close QUIC connection with server.
  virtual void Close() = 0;
  // Create a bidirectional stream.
  virtual WebTransportStreamInterface* CreateBidirectionalStream() = 0;
  // Create an ougoing unidirectional stream.
  virtual WebTransportStreamInterface*
  CreateOutgoingUnidirectionalStream() = 0;
};
}  // namespace quic
}  // namespace owt

#endif