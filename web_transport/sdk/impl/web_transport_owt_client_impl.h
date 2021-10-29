/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_WEB_TRANSPORT_WEB_TRANSPORT_WEB_TRANSPORT_OWT_CLIENT_IMPL_H_
#define OWT_WEB_TRANSPORT_WEB_TRANSPORT_WEB_TRANSPORT_OWT_CLIENT_IMPL_H_

#include "base/memory/weak_ptr.h"
#include "base/threading/thread.h"
#include "owt/quic/web_transport_client_interface.h"
#include "owt/web_transport/sdk/impl/web_transport_http3_client.h"
#include "owt/web_transport/sdk/impl/web_transport_stream_impl.h"
#include "url/gurl.h"

namespace owt {
namespace quic {
// A HTTP/3 based WebTransport client. No HTTP/2 support.
// This class is thread-safe. All calls to //net will be delegated to
// io_thread_.
class WebTransportOwtClientImpl : public WebTransportClientInterface,
                                  public net::WebTransportClientVisitor {
 public:
  WebTransportOwtClientImpl(const GURL& url,
                            const url::Origin& origin,
                            base::Thread* io_thread,
                            base::Thread* event_thread);
  WebTransportOwtClientImpl(const GURL& url,
                            const url::Origin& origin,
                            const net::WebTransportParameters& parameters,
                            base::Thread* io_thread,
                            base::Thread* event_thread);
  // `context` could has its user defined wall time, which can be used for
  // certificate verification in testing.
  WebTransportOwtClientImpl(const GURL& url,
                            const url::Origin& origin,
                            const net::WebTransportParameters& parameters,
                            net::URLRequestContext* context,
                            base::Thread* io_thread,
                            base::Thread* event_thread);
  ~WebTransportOwtClientImpl() override;

  void SetVisitor(WebTransportClientInterface::Visitor* visitor) override;
  void Connect() override;
  void Close() override;
  WebTransportStreamInterface* CreateBidirectionalStream() override;
  WebTransportStreamInterface* CreateOutgoingUnidirectionalStream() override;
  MessageStatus SendOrQueueDatagram(uint8_t* data, size_t length) override;

 protected:
  // Overrides net::WebTransportClientVisitor.
  void OnConnected(
      scoped_refptr<net::HttpResponseHeaders> response_headers) override;
  void OnConnectionFailed(const net::WebTransportError& error) override;
  void OnClosed(
      const absl::optional<net::WebTransportCloseInfo>& close_info) override;
  void OnError(const net::WebTransportError& error) override;
  void OnIncomingBidirectionalStreamAvailable() override;
  void OnIncomingUnidirectionalStreamAvailable() override;
  void OnDatagramReceived(base::StringPiece datagram) override {}
  void OnCanCreateNewOutgoingBidirectionalStream() override {}
  void OnCanCreateNewOutgoingUnidirectionalStream() override {}
  void OnDatagramProcessed(
      absl::optional<::quic::MessageStatus> status) override;

 private:
  void ConnectOnCurrentThread(base::WaitableEvent* event);
  void CloseOnCurrentThread(base::WaitableEvent* event);
  WebTransportStreamInterface* CreateOutgoingStream(bool bidirectional);
  WebTransportStreamInterface* CreateOutgoingStreamOnCurrentThread(
      bool bidirectional);
  void OnIncomingStreamAvailable(bool bidirectional);
  // This method also adds created stream to `streams_`.
  WebTransportStreamInterface* OwtStreamForNativeStream(
      ::quic::WebTransportStream* stream);
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
  std::unique_ptr<WebTransportHttp3Client> client_;
  WebTransportClientInterface::Visitor* visitor_;
  // TODO: Pop from the vector when a stream is closed.
  std::vector<std::unique_ptr<WebTransportStreamImpl>> streams_;

  base::WeakPtrFactory<WebTransportOwtClientImpl> weak_factory_{this};
};
}  // namespace quic
}  // namespace owt

#endif