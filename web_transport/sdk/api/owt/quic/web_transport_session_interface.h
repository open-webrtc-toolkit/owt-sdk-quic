/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_WEB_TRANSPORT_WEB_TRANSPORT_SESSION_INTERFACE_H_
#define OWT_WEB_TRANSPORT_WEB_TRANSPORT_SESSION_INTERFACE_H_

#include "owt/quic/export.h"
#include "owt/quic/web_transport_definitions.h"
#include "owt/quic/web_transport_stream_interface.h"

namespace owt {
namespace quic {
class OWT_EXPORT WebTransportSessionInterface {
 public:
  class Visitor {
   public:
    virtual ~Visitor() = default;
    virtual void OnIncomingStream(WebTransportStreamInterface*) = 0;
    virtual void OnCanCreateNewOutgoingStream(bool unidirectional) = 0;
    virtual void OnConnectionClosed() = 0;
  };
  virtual ~WebTransportSessionInterface() = default;
  virtual const char* ConnectionId() const = 0;
  virtual void SetVisitor(Visitor* visitor) = 0;
  virtual bool IsSessionReady() const = 0;
  virtual WebTransportStreamInterface* CreateBidirectionalStream() = 0;
  virtual MessageStatus SendOrQueueDatagram(uint8_t* data, size_t length) = 0;
  // Get connection stats.
  virtual const ConnectionStats& GetStats() = 0;
  // Close a WebTransport session. `code` is the error code communicated with
  // peer, `reason` is a pointer to a UTF-8 encoded null terminated string, its
  // length should not exceed 1024.
  virtual void Close(uint32_t code, const char* reason) = 0;
};
}  // namespace quic
}  // namespace owt

#endif