/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_OWT_CLIENT_IMPL_H_
#define OWT_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_OWT_CLIENT_IMPL_H_

#include "net/quic/quic_transport_client.h"
#include "owt/quic/quic_transport_client_interface.h"
#include "url/gurl.h"

namespace owt {
namespace quic {
// A server accepts WebTransport - QuicTransport connections.
class QuicTransportOwtClientImpl : public QuicTransportClientInterface,
                                   public net::QuicTransportClient::Visitor {
 public:
  ~QuicTransportOwtClientImpl() override;
  QuicTransportOwtClientImpl(const GURL& url);
  void Connect() override;

protected:
  // Overrides net::QuicTransportClient::Visitor.
 void OnConnected() override{}
 void OnConnectionFailed() override{}
 void OnClosed() override{}
 void OnError() override{}
 void OnIncomingBidirectionalStreamAvailable() override{}
 void OnIncomingUnidirectionalStreamAvailable() override{}
 void OnDatagramReceived(base::StringPiece datagram) override{}
 void OnCanCreateNewOutgoingBidirectionalStream() override{}
 void OnCanCreateNewOutgoingUnidirectionalStream() override{}

private:
 std::unique_ptr<net::URLRequestContext> context_;
 std::unique_ptr<net::QuicTransportClient> client_;
};
}  // namespace quic
}  // namespace owt

#endif