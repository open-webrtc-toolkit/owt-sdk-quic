/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_TRANSPORT_CLIENT_INTERFACE_H_
#define OWT_QUIC_TRANSPORT_CLIENT_INTERFACE_H_

#include "owt/quic/export.h"
#include "owt/quic/quic_transport_stream_interface.h"

namespace owt {
namespace quic {
// A client manages a QuicTransport session with a QuicTransport server.
class OWT_EXPORT QuicTransportClientInterface {
 public:
  // https://wicg.github.io/web-transport/#dom-quictransportconfiguration-server_certificate_fingerprints.
  class Visitor {
   public:
    virtual ~Visitor() = default;
    // Called when the connection state changed from connecting to connected.
    virtual void OnConnected() = 0;
    // Called when the connection state changed from connecting to failed.
    virtual void OnConnectionFailed() = 0;
    // Called when a session is closed.
    virtual void OnConnectionClosed(char*, size_t len) = 0;
    // Called when an incoming stream is received.
    virtual void OnIncomingStream(QuicTransportStreamInterface*) = 0;
    //Called when a stream is closed
    virtual void OnStreamClosed(uint32_t id) = 0;
  };

  virtual ~QuicTransportClientInterface() = default;
  // Set a visitor for the client.
  virtual void SetVisitor(Visitor* visitor) = 0;
  virtual void Start() = 0;
  // Close QuicTransport session with server.
  virtual void Stop() = 0;

  virtual const char* Id() = 0;
  virtual uint8_t length() = 0;
  // Create a bidirectional stream.
  virtual QuicTransportStreamInterface* CreateBidirectionalStream() = 0;
};
}  // namespace quic
}

#endif