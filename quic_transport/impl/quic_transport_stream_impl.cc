/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "impl/quic_transport_stream_impl.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_stream.h"

namespace owt {
namespace quic {

class VisitorAdapter : public ::quic::QuicTransportStream::Visitor {
 public:
  VisitorAdapter(::quic::QuicTransportStream::Visitor* visitor)
      : visitor_(visitor) {}

  void OnCanRead() override {
    if (visitor_) {
      visitor_->OnCanRead();
    }
  }
  void OnFinRead() override {}
  void OnCanWrite() override {}

 private:
  ::quic::QuicTransportStream::Visitor* visitor_;
};

QuicTransportStreamImpl::QuicTransportStreamImpl(
    ::quic::QuicTransportStream* stream)
    : stream_(stream), visitor_(nullptr) {
  stream_->set_visitor(std::make_unique<VisitorAdapter>(this));
}

QuicTransportStreamImpl::~QuicTransportStreamImpl() = default;

void QuicTransportStreamImpl::SetVisitor(
    owt::quic::QuicTransportStreamInterface::Visitor* visitor) {
  visitor_ = visitor;
}

void QuicTransportStreamImpl::OnCanRead() {
  LOG(INFO) << "OnCanRead.";
  if (visitor_) {
    visitor_->OnCanRead();
  }
}
void QuicTransportStreamImpl::OnFinRead() {
  LOG(INFO) << "OnFinRead.";
  // TODO:
}
void QuicTransportStreamImpl::OnCanWrite() {
  LOG(INFO) << "OnCanWrite.";
  if (visitor_) {
    visitor_->OnCanWrite();
  }
}

}  // namespace quic
}  // namespace owt