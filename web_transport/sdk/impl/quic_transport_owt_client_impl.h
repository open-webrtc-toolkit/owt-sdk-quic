/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_WEB_TRANSPORT_WEB_TRANSPORT_QUIC_TRANSPORT_OWT_CLIENT_IMPL_H_
#define OWT_WEB_TRANSPORT_WEB_TRANSPORT_QUIC_TRANSPORT_OWT_CLIENT_IMPL_H_

#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "net/quic/quic_transport_client.h"
#include "owt/quic/web_transport_client_interface.h"
#include "owt/web_transport/sdk/impl/quic_transport_stream_impl.h"
#include "url/gurl.h"

namespace owt {
namespace quic {
// A server accepts WebTransport - QuicTransport connections.
// This class is thread-safe. All calls to //net will be delegated to
// io_thread_.
class QuicTransportOwtClientImpl : public WebTransportClientInterface,
                                   public net::WebTransportClientVisitor {
 public:
  QuicTransportOwtClientImpl(const GURL& url,
                             const url::Origin& origin,
                             base::Thread* io_thread,
                             base::Thread* event_thread);
  QuicTransportOwtClientImpl(
      const GURL& url,
      const url::Origin& origin,
      const net::WebTransportParameters& parameters,
      base::Thread* io_thread,
      base::Thread* event_thread);
  // `context` could has its user defined wall time, which can be used for
  // certificate verification in testing.
  QuicTransportOwtClientImpl(
      const GURL& url,
      const url::Origin& origin,
      const net::WebTransportParameters& parameters,
      net::URLRequestContext* context,
      base::Thread* io_thread,
      base::Thread* event_thread);
  ~QuicTransportOwtClientImpl() override;

  void SetVisitor(WebTransportClientInterface::Visitor* visitor) override;
  void Connect() override;
  void Close() override;
  WebTransportStreamInterface* CreateBidirectionalStream() override;
  WebTransportStreamInterface* CreateOutgoingUnidirectionalStream() override;

 protected:
  // Overrides net::WebTransportClientVisitor.
  void OnConnected() override;
  void OnConnectionFailed() override;
  void OnClosed() override {}
  void OnError() override {}
  void OnIncomingBidirectionalStreamAvailable() override;
  void OnIncomingUnidirectionalStreamAvailable() override;
  void OnDatagramReceived(base::StringPiece datagram) override {}
  void OnCanCreateNewOutgoingBidirectionalStream() override {}
  void OnCanCreateNewOutgoingUnidirectionalStream() override {}
  void OnDatagramProcessed(
      absl::optional<::quic::MessageStatus> status) override {}

 private:
  void ConnectOnCurrentThread(base::WaitableEvent* event);
  void CloseOnCurrentThread(base::WaitableEvent* event);
  WebTransportStreamInterface* CreateOutgoingStream(bool bidirectional);
  WebTransportStreamInterface* CreateOutgoingStreamOnCurrentThread(
      bool bidirectional);
  void OnIncomingStreamAvailable(bool bidirectional);
  // This method also adds created stream to `streams_`.
  WebTransportStreamInterface* OwtStreamForNativeStream(
      ::quic::QuicTransportStream* stream);
  void FireEvent(
      std::function<void(WebTransportClientInterface::Visitor&)> func);

  std::unique_ptr<base::Thread> io_thread_owned_;
  GURL url_;
  url::Origin origin_;
  net::WebTransportParameters parameters_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> event_runner_;
  std::unique_ptr<net::URLRequestContext> context_owned_;
  net::URLRequestContext* context_;
  std::unique_ptr<net::QuicTransportClient> client_;
  WebTransportClientInterface::Visitor* visitor_;
  std::vector<std::unique_ptr<QuicTransportStreamImpl>> streams_;

  base::WeakPtrFactory<QuicTransportOwtClientImpl> weak_factory_{this};
};
}  // namespace quic
}  // namespace owt

#endif