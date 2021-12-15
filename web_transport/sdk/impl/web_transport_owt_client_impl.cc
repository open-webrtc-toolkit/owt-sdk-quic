/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "impl/web_transport_owt_client_impl.h"
#include "base/threading/thread.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/third_party/quiche/src/quic/core/web_transport_interface.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "owt/web_transport/sdk/impl/utilities.h"

namespace owt {
namespace quic {
WebTransportOwtClientImpl::WebTransportOwtClientImpl(const GURL& url,
                                                     const url::Origin& origin,
                                                     base::Thread* io_thread,
                                                     base::Thread* event_thread)
    : WebTransportOwtClientImpl(url,
                                origin,
                                net::WebTransportParameters(),
                                io_thread,
                                event_thread) {}

WebTransportOwtClientImpl::WebTransportOwtClientImpl(
    const GURL& url,
    const url::Origin& origin,
    const net::WebTransportParameters& parameters,
    base::Thread* io_thread,
    base::Thread* event_thread)
    : WebTransportOwtClientImpl(url,
                                origin,
                                parameters,
                                nullptr,
                                io_thread,
                                event_thread) {}

WebTransportOwtClientImpl::WebTransportOwtClientImpl(
    const GURL& url,
    const url::Origin& origin,
    const net::WebTransportParameters& parameters,
    net::URLRequestContext* context,
    base::Thread* io_thread,
    base::Thread* event_thread)
    : url_(url),
      origin_(origin),
      parameters_(parameters),
      event_runner_(event_thread->task_runner()),
      context_(context) {
  CHECK(event_runner_);
  if (!io_thread) {
    LOG(INFO) << "Create a new IO stream.";
    io_thread_owned_ =
        std::make_unique<base::Thread>("quic_transport_client_io_thread");
    io_thread_owned_->StartWithOptions(
        base::Thread::Options(base::MessagePumpType::IO, 0));
    task_runner_ = io_thread_owned_->task_runner();
  } else {
    task_runner_ = io_thread->task_runner();
  }
  if (context == nullptr) {
    net::URLRequestContextBuilder builder;
    builder.set_proxy_resolution_service(
        net::ConfiguredProxyResolutionService::CreateDirect());
    context_owned_ = builder.Build();
    context_ = context_owned_.get();
  }
}

WebTransportOwtClientImpl::~WebTransportOwtClientImpl() {
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(
                     [](std::unique_ptr<net::WebTransportClient> client,
                        std::unique_ptr<net::URLRequestContext> context,
                        base::WaitableEvent* event) {
                       if (client) {
                         client.reset();
                       }
                       if (context) {
                         context.reset();
                       }
                       event->Signal();
                     },
                     std::move(client_), std::move(context_owned_), &done));
  done.Wait();
}

void WebTransportOwtClientImpl::Connect() {
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&WebTransportOwtClientImpl::ConnectOnCurrentThread,
                     base::Unretained(this), &done));
  done.Wait();
}

void WebTransportOwtClientImpl::Close() {
  LOG(WARNING) << "Close is not implemented.";
}

void WebTransportOwtClientImpl::ConnectOnCurrentThread(
    base::WaitableEvent* event) {
  CHECK(context_);
  CHECK(context_->quic_context());
  client_ = std::make_unique<WebTransportHttp3Client>(
      url_, origin_, this, net::NetworkIsolationKey(origin_, origin_), context_,
      parameters_);
  client_->Connect();
  event->Signal();
}

void WebTransportOwtClientImpl::CloseOnCurrentThread(
    base::WaitableEvent* event) {
  LOG(WARNING) << "Close is not implemented.";
  event->Signal();
}

void WebTransportOwtClientImpl::SetVisitor(
    WebTransportClientInterface::Visitor* visitor) {
  visitor_ = visitor;
}

void WebTransportOwtClientImpl::OnConnected(
    scoped_refptr<net::HttpResponseHeaders> response_headers) {
  LOG(INFO) << "OnConnected.";
  event_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&WebTransportOwtClientImpl::FireEvent,
                     weak_factory_.GetWeakPtr(),
                     &WebTransportClientInterface::Visitor::OnConnected));
}

void WebTransportOwtClientImpl::OnConnectionFailed(
    const net::WebTransportError& error) {
  LOG(INFO) << "OnConnectionFailed.";
  event_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          &WebTransportOwtClientImpl::FireEvent, weak_factory_.GetWeakPtr(),
          &WebTransportClientInterface::Visitor::OnConnectionFailed));
}

void WebTransportOwtClientImpl::OnError(const net::WebTransportError& error) {
  LOG(INFO) << "OnError.";
}

void WebTransportOwtClientImpl::OnClosed(
    const absl::optional<net::WebTransportCloseInfo>& close_info) {
  if (!visitor_) {
    return;
  }
  visitor_->OnClosed(
      close_info.has_value() ? close_info->code : 0,
      close_info.has_value() ? nullptr : close_info->reason.c_str());
}

WebTransportStreamInterface*
WebTransportOwtClientImpl::CreateBidirectionalStream() {
  return CreateOutgoingStream(true);
}

WebTransportStreamInterface*
WebTransportOwtClientImpl::CreateOutgoingUnidirectionalStream() {
  return CreateOutgoingStream(false);
}

WebTransportStreamInterface* WebTransportOwtClientImpl::CreateOutgoingStream(
    bool bidirectional) {
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  WebTransportStreamInterface* stream(nullptr);
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(
                     [](WebTransportOwtClientImpl* client,
                        WebTransportStreamInterface** result,
                        bool bidirectional, base::WaitableEvent* event) {
                       CHECK(client);
                       *result = client->CreateOutgoingStreamOnCurrentThread(
                           bidirectional);
                       event->Signal();
                     },
                     base::Unretained(this), base::Unretained(&stream),
                     bidirectional, base::Unretained(&done)));
  done.Wait();
  return stream;
}

WebTransportStreamInterface*
WebTransportOwtClientImpl::CreateOutgoingStreamOnCurrentThread(
    bool bidirectional) {
  ::quic::WebTransportStream* stream(nullptr);
  if (bidirectional) {
    if (!client_->session()->CanOpenNextOutgoingBidirectionalStream()) {
      return nullptr;
    }
    stream = client_->session()->OpenOutgoingBidirectionalStream();
  } else {
    if (!client_->session()->CanOpenNextOutgoingUnidirectionalStream()) {
      return nullptr;
    }
    stream = client_->session()->OpenOutgoingUnidirectionalStream();
  }
  DCHECK(stream);
  return OwtStreamForNativeStream(stream);
}

void WebTransportOwtClientImpl::OnIncomingBidirectionalStreamAvailable() {
  event_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&WebTransportOwtClientImpl::OnIncomingStreamAvailable,
                     weak_factory_.GetWeakPtr(), true));
}

void WebTransportOwtClientImpl::OnIncomingUnidirectionalStreamAvailable() {
  event_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&WebTransportOwtClientImpl::OnIncomingStreamAvailable,
                     weak_factory_.GetWeakPtr(), false));
}

void WebTransportOwtClientImpl::OnIncomingStreamAvailable(bool bidirectional) {
  auto* stream = bidirectional
                     ? client_->session()->AcceptIncomingBidirectionalStream()
                     : client_->session()->AcceptIncomingUnidirectionalStream();
  CHECK(stream);
  if (visitor_) {
    auto* owt_stream = OwtStreamForNativeStream(stream);
    CHECK(owt_stream);
    visitor_->OnIncomingStream(owt_stream);
  } else {
    // No one cares about incoming streams.
    DCHECK(stream->SendFin());
  }
}

void WebTransportOwtClientImpl::OnDatagramProcessed(
    absl::optional<::quic::MessageStatus> status) {
  if (visitor_) {
    visitor_->OnDatagramProcessed(Utilities::ConvertMessageStatus(status));
  }
}

WebTransportStreamInterface*
WebTransportOwtClientImpl::OwtStreamForNativeStream(
    ::quic::WebTransportStream* stream) {
  std::unique_ptr<WebTransportStreamImpl> stream_impl =
      std::make_unique<WebTransportStreamImpl>(
          stream,
          client_->quic_session()->GetOrCreateStream(stream->GetStreamId()),
          task_runner_.get(), event_runner_.get());
  WebTransportStreamImpl* stream_ptr(stream_impl.get());
  streams_.push_back(std::move(stream_impl));
  return stream_ptr;
}

void WebTransportOwtClientImpl::FireEvent(
    std::function<void(WebTransportClientInterface::Visitor&)> func) {
  if (visitor_) {
    func(*visitor_);
  }
}

MessageStatus WebTransportOwtClientImpl::SendOrQueueDatagram(uint8_t* data,
                                                             size_t length) {
  DCHECK(client_ && client_->quic_session() &&
         client_->quic_session()->connection() &&
         client_->quic_session()->connection()->helper());
  auto* allocator = client_->quic_session()
                        ->connection()
                        ->helper()
                        ->GetStreamSendBufferAllocator();
  ::quic::QuicBuffer buffer = ::quic::QuicBuffer::Copy(
      allocator, absl::string_view(reinterpret_cast<char*>(data), length));
  if (task_runner_->BelongsToCurrentThread()) {
    auto message_result = client_->session()->SendOrQueueDatagram(
        ::quic::QuicMemSlice(std::move(buffer)));
    return Utilities::ConvertMessageStatus(message_result);
  }
  MessageStatus result;
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](WebTransportOwtClientImpl* client, ::quic::QuicMemSlice slice,
             MessageStatus& result, base::WaitableEvent* event) {
            auto message_result =
                client->client_->session()->SendOrQueueDatagram(
                    std::move(slice));
            result = Utilities::ConvertMessageStatus(message_result);
            event->Signal();
          },
          base::Unretained(this), ::quic::QuicMemSlice(std::move(buffer)),
          std::ref(result), base::Unretained(&done)));
  done.Wait();
  return result;
}

}  // namespace quic
}  // namespace owt
