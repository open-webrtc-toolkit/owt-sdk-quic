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
  url::Origin origin = url::Origin::Create(url);
  net::URLRequestContextBuilder builder;
  context_ = builder.Build();
  net::QuicTransportClient::Parameters parameters;
  client_ = std::make_unique<net::QuicTransportClient>(
      url, origin, this, net::NetworkIsolationKey(origin, origin),
      context_.get(), parameters);
}

QuicTransportOwtClientImpl::~QuicTransportOwtClientImpl() {}

void QuicTransportOwtClientImpl::Connect() {
  client_->Connect();
}

}  // namespace quic
}  // namespace owt
