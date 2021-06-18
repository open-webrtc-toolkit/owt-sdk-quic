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
    base::Thread* io_thread,
    base::Thread* event_thread)
    : QuicTransportOwtClientImpl(url,
                                 origin,
                                 net::WebTransportParameters(),
                                 io_thread,
                                 event_thread) {}

QuicTransportOwtClientImpl::QuicTransportOwtClientImpl(
    const GURL& url,
    const url::Origin& origin,
    const net::WebTransportParameters& parameters,
    base::Thread* io_thread,
    base::Thread* event_thread)
    : QuicTransportOwtClientImpl(url,
                                 origin,
                                 parameters,
                                 nullptr,
                                 io_thread,
                                 event_thread) {}

QuicTransportOwtClientImpl::QuicTransportOwtClientImpl(
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
      FROM_HERE,
      base::BindOnce(&QuicTransportOwtClientImpl::CloseOnCurrentThread,
                     base::Unretained(this), &done));
  done.Wait();
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

void QuicTransportOwtClientImpl::Close() {
  VLOG(1) << "Closing QuicTransportOwtClient.";
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicTransportOwtClientImpl::CloseOnCurrentThread,
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

void QuicTransportOwtClientImpl::CloseOnCurrentThread(
    base::WaitableEvent* event) {
  if (client_ == nullptr) {
    event->Signal();
    return;
  }
  if (client_->quic_session() == nullptr) {
    event->Signal();
    return;
  }
  if (client_->quic_session()->connection() == nullptr) {
    event->Signal();
    return;
  }
  CHECK(client_);
  CHECK(client_->quic_session());
  CHECK(client_->quic_session()->connection());
  // Above code just makes code scan tools happy.
  if (client_ && client_->quic_session() &&
      client_->quic_session()->connection()) {
    client_->quic_session()->connection()->CloseConnection(
        ::quic::QuicErrorCode::QUIC_NO_ERROR, "Close connection.",
        ::quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
  event->Signal();
}

void QuicTransportOwtClientImpl::SetVisitor(
    WebTransportClientInterface::Visitor* visitor) {
  visitor_ = visitor;
}

void QuicTransportOwtClientImpl::OnConnected() {
  event_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicTransportOwtClientImpl::FireEvent,
                     weak_factory_.GetWeakPtr(),
                     &WebTransportClientInterface::Visitor::OnConnected));
}

void QuicTransportOwtClientImpl::OnConnectionFailed() {
  event_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          &QuicTransportOwtClientImpl::FireEvent, weak_factory_.GetWeakPtr(),
          &WebTransportClientInterface::Visitor::OnConnectionFailed));
}

WebTransportStreamInterface*
QuicTransportOwtClientImpl::CreateBidirectionalStream() {
  return CreateOutgoingStream(true);
}

WebTransportStreamInterface*
QuicTransportOwtClientImpl::CreateOutgoingUnidirectionalStream() {
  return CreateOutgoingStream(false);
}

WebTransportStreamInterface* QuicTransportOwtClientImpl::CreateOutgoingStream(
    bool bidirectional) {
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  WebTransportStreamInterface* stream(nullptr);
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(
                     [](QuicTransportOwtClientImpl* client,
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
QuicTransportOwtClientImpl::CreateOutgoingStreamOnCurrentThread(
    bool bidirectional) {
  if (!client_->quic_session()) {
    return nullptr;
  }
  ::quic::QuicTransportStream* stream =
      bidirectional ? client_->quic_session()->OpenOutgoingBidirectionalStream()
                    : client_->quic_session()->OpenOutgoingUnidirectionalStream();
  return OwtStreamForNativeStream(stream);
}

void QuicTransportOwtClientImpl::OnIncomingBidirectionalStreamAvailable() {
  event_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicTransportOwtClientImpl::OnIncomingStreamAvailable,
                     weak_factory_.GetWeakPtr(), true));
}

void QuicTransportOwtClientImpl::OnIncomingUnidirectionalStreamAvailable() {
  event_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicTransportOwtClientImpl::OnIncomingStreamAvailable,
                     weak_factory_.GetWeakPtr(), false));
}

void QuicTransportOwtClientImpl::OnIncomingStreamAvailable(bool bidirectional) {
  auto* stream = bidirectional
                     ? client_->quic_session()->AcceptIncomingBidirectionalStream()
                     : client_->quic_session()->AcceptIncomingUnidirectionalStream();
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

WebTransportStreamInterface*
QuicTransportOwtClientImpl::OwtStreamForNativeStream(
    ::quic::QuicTransportStream* stream) {
  std::unique_ptr<QuicTransportStreamImpl> stream_impl =
      std::make_unique<QuicTransportStreamImpl>(stream, task_runner_.get(),
                                                event_runner_.get());
  QuicTransportStreamImpl* stream_ptr(stream_impl.get());
  streams_.push_back(std::move(stream_impl));
  return stream_ptr;
}

void QuicTransportOwtClientImpl::FireEvent(
    std::function<void(WebTransportClientInterface::Visitor&)> func) {
  if (visitor_) {
    func(*visitor_);
  }
}

}  // namespace quic
}  // namespace owt
