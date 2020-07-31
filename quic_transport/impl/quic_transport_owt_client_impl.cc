/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "impl/quic_transport_owt_client_impl.h"
#include "base/threading/thread.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"

namespace owt {
namespace quic {
QuicTransportOwtClientImpl::QuicTransportOwtClientImpl(
    const GURL& url,
    const url::Origin& origin,
    base::Thread* thread)
    : QuicTransportOwtClientImpl(url,
                                 origin,
                                 net::QuicTransportClient::Parameters(),
                                 thread) {}

QuicTransportOwtClientImpl::QuicTransportOwtClientImpl(
    const GURL& url,
    const url::Origin& origin,
    const net::QuicTransportClient::Parameters& parameters,
    base::Thread* thread)
    : QuicTransportOwtClientImpl(url, origin, parameters, nullptr, thread) {}

QuicTransportOwtClientImpl::QuicTransportOwtClientImpl(
    const GURL& url,
    const url::Origin& origin,
    const net::QuicTransportClient::Parameters& parameters,
    net::URLRequestContext* context,
    base::Thread* io_thread)
    : url_(url), origin_(origin), parameters_(parameters), context_(context) {
  if (!io_thread) {
    LOG(INFO) << "Create a new IO stream.";
    io_thread_owned_ =
        std::make_unique<base::Thread>("quic_transport_client_io_thread");
    base::Thread::Options options;
    options.message_pump_type = base::MessagePumpType::IO;
    io_thread_owned_->StartWithOptions(options);
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

QuicTransportOwtClientImpl::~QuicTransportOwtClientImpl() {
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(
                     [](std::unique_ptr<net::QuicTransportClient> client,
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

void QuicTransportOwtClientImpl::Connect() {
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicTransportOwtClientImpl::ConnectOnCurrentThread,
                     base::Unretained(this), &done));
  done.Wait();
}

void QuicTransportOwtClientImpl::ConnectOnCurrentThread(
    base::WaitableEvent* event) {
  CHECK(context_);
  CHECK(context_->quic_context());
  client_ = std::make_unique<net::QuicTransportClient>(
      url_, origin_, this, net::NetworkIsolationKey(origin_, origin_), context_,
      parameters_);
  client_->Connect();
  event->Signal();
}

void QuicTransportOwtClientImpl::SetVisitor(
    QuicTransportClientInterface::Visitor* visitor) {
  visitor_ = visitor;
}

void QuicTransportOwtClientImpl::OnConnected() {
  if (visitor_) {
    visitor_->OnConnected();
  }
}

void QuicTransportOwtClientImpl::OnConnectionFailed() {
  if (visitor_) {
    visitor_->OnConnectionFailed();
  }
}

QuicTransportStreamInterface*
QuicTransportOwtClientImpl::CreateBidirectionalStream() {
  return CreateOutgoingStream(true);
}

QuicTransportStreamInterface*
QuicTransportOwtClientImpl::CreateOutgoingUnidirectionalStream() {
  return CreateOutgoingStream(false);
}

QuicTransportStreamInterface* QuicTransportOwtClientImpl::CreateOutgoingStream(
    bool bidirectional) {
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  QuicTransportStreamInterface* stream(nullptr);
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(
                     [](QuicTransportOwtClientImpl* client,
                        QuicTransportStreamInterface** result,
                        bool bidirectional, base::WaitableEvent* event) {
                       *result = client->CreateOutgoingStreamOnCurrentThread(
                           bidirectional);
                       event->Signal();
                     },
                     base::Unretained(this), base::Unretained(&stream),
                     bidirectional, base::Unretained(&done)));
  done.Wait();
  return stream;
}

QuicTransportStreamInterface*
QuicTransportOwtClientImpl::CreateOutgoingStreamOnCurrentThread(
    bool bidirectional) {
  ::quic::QuicTransportStream* stream =
      bidirectional ? client_->session()->OpenOutgoingBidirectionalStream()
                    : client_->session()->OpenOutgoingUnidirectionalStream();
  return OwtStreamForNativeStream(stream);
}

void QuicTransportOwtClientImpl::OnIncomingBidirectionalStreamAvailable() {
  OnIncomingStreamAvailable(true);
}

void QuicTransportOwtClientImpl::OnIncomingUnidirectionalStreamAvailable() {
  OnIncomingStreamAvailable(false);
}

void QuicTransportOwtClientImpl::OnIncomingStreamAvailable(bool bidirectional) {
  auto* stream = bidirectional
                     ? client_->session()->AcceptIncomingBidirectionalStream()
                     : client_->session()->AcceptIncomingUnidirectionalStream();
  CHECK(stream);
  if (visitor_) {
    auto* owt_stream = OwtStreamForNativeStream(stream);
    visitor_->OnIncomingStream(owt_stream);
  } else {
    // No one cares about incoming streams.
    DCHECK(stream->SendFin());
  }
}

QuicTransportStreamInterface*
QuicTransportOwtClientImpl::OwtStreamForNativeStream(
    ::quic::QuicTransportStream* stream) {
  std::unique_ptr<QuicTransportStreamImpl> stream_impl =
      std::make_unique<QuicTransportStreamImpl>(stream, task_runner_.get());
  QuicTransportStreamImpl* stream_ptr(stream_impl.get());
  streams_.push_back(std::move(stream_impl));
  return stream_ptr;
}

}  // namespace quic
}  // namespace owt
