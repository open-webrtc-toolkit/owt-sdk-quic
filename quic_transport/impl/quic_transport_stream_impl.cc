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
    ::quic::QuicTransportStream* stream,
    base::TaskRunner* runner)
    : stream_(stream), runner_(runner), visitor_(nullptr) {
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

void QuicTransportStreamImpl::Write(uint8_t* data, size_t length) {
  CHECK(runner_);
  runner_->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(
          &::quic::QuicTransportStream::Write, base::Unretained(stream_),
          quiche::QuicheStringPiece(reinterpret_cast<char*>(data), length)),
      base::BindOnce([](bool result) { DCHECK(result); }));
}

void QuicTransportStreamImpl::Close() {
  CHECK(runner_);
  runner_->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(&::quic::QuicTransportStream::SendFin,
                     base::Unretained(stream_)),
      base::BindOnce([](bool result) { DCHECK(result); }));
}

}  // namespace quic
}  // namespace owt