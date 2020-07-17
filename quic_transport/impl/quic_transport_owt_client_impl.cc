/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "impl/quic_transport_owt_client_impl.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"

namespace owt {
namespace quic {
QuicTransportOwtClientImpl::QuicTransportOwtClientImpl(const GURL& url) {
  net::QuicTransportClient::Parameters parameters;
  QuicTransportOwtClientImpl(url, parameters);
}

QuicTransportOwtClientImpl::QuicTransportOwtClientImpl(
    const GURL& url,
    const net::QuicTransportClient::Parameters& parameters) {
  url::Origin origin = url::Origin::Create(url);
  net::URLRequestContextBuilder builder;
  context_ = builder.Build();
  client_ = std::make_unique<net::QuicTransportClient>(
      url, origin, this, net::NetworkIsolationKey(origin, origin),
      context_.get(), parameters);
}

QuicTransportOwtClientImpl::~QuicTransportOwtClientImpl() {}

void QuicTransportOwtClientImpl::Connect() {
  client_->Connect();
}

void QuicTransportOwtClientImpl::SetVisitor(
    QuicTransportClientInterface::Visitor* visitor) {
  visitor_ = visitor;
}

}  // namespace quic
}  // namespace owt
