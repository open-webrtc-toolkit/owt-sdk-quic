/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_OWT_CLIENT_IMPL_H_
#define OWT_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_OWT_CLIENT_IMPL_H_

#include "base/single_thread_task_runner.h"
#include "net/quic/quic_transport_client.h"
#include "owt/quic/quic_transport_client_interface.h"
#include "owt/quic_transport/impl/quic_transport_stream_impl.h"
#include "url/gurl.h"

namespace owt {
namespace quic {
// A server accepts WebTransport - QuicTransport connections.
// This class is thread-safe. All calls to //net will be delegated to
// io_thread_.
class QuicTransportOwtClientImpl : public QuicTransportClientInterface,
                                   public net::QuicTransportClient::Visitor {
 public:
  QuicTransportOwtClientImpl(const GURL& url,
                             const url::Origin& origin,
                             base::Thread* thread);
  QuicTransportOwtClientImpl(
      const GURL& url,
      const url::Origin& origin,
      const net::QuicTransportClient::Parameters& parameters,
      base::Thread* thread);
  // `context` could has its user defined wall time, which can be used for
  // certificate verification in testing.
  QuicTransportOwtClientImpl(
      const GURL& url,
      const url::Origin& origin,
      const net::QuicTransportClient::Parameters& parameters,
      net::URLRequestContext* context,
      base::Thread* io_thread);
  ~QuicTransportOwtClientImpl() override;

  void SetVisitor(QuicTransportClientInterface::Visitor* visitor) override;
  void Connect() override;
  QuicTransportStreamInterface* CreateBidirectionalStream() override;

 protected:
  // Overrides net::QuicTransportClient::Visitor.
  void OnConnected() override;
  void OnConnectionFailed() override;
  void OnClosed() override {}
  void OnError() override {}
  void OnIncomingBidirectionalStreamAvailable() override {}
  void OnIncomingUnidirectionalStreamAvailable() override {}
  void OnDatagramReceived(base::StringPiece datagram) override {}
  void OnCanCreateNewOutgoingBidirectionalStream() override {}
  void OnCanCreateNewOutgoingUnidirectionalStream() override {}

  void ConnectOnCurrentThread(base::WaitableEvent* event);
  QuicTransportStreamInterface* CreateBidirectionalStreamOnCurrentThread();

 private:
  std::unique_ptr<base::Thread> io_thread_owned_;
  GURL url_;
  url::Origin origin_;
  net::QuicTransportClient::Parameters parameters_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  std::unique_ptr<net::URLRequestContext> context_owned_;
  net::URLRequestContext* context_;
  std::unique_ptr<net::QuicTransportClient> client_;
  QuicTransportClientInterface::Visitor* visitor_;
  std::vector<std::unique_ptr<QuicTransportStreamImpl>> streams_;
};
}  // namespace quic
}  // namespace owt

#endif