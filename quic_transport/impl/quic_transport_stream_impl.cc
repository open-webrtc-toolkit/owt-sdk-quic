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
    LOG(INFO) << "OnCanRead";
    if (visitor_) {
      visitor_->OnCanRead();
    }
  }
  void OnFinRead() override {}
  void OnCanWrite() override {
    if(visitor_){
      visitor_->OnCanWrite();
    }
  }

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
  if (visitor_) {
    visitor_->OnCanRead();
  }
}
void QuicTransportStreamImpl::OnFinRead() {
  LOG(INFO) << "OnFinRead.";
  // TODO:
}
void QuicTransportStreamImpl::OnCanWrite() {
  if (visitor_) {
    visitor_->OnCanWrite();
  }
}

uint32_t QuicTransportStreamImpl::Id() const {
  return stream_->id();
}

void QuicTransportStreamImpl::Write(uint8_t* data, size_t length) {
  std::vector<uint8_t> data_copy(data, data + length);
  CHECK(runner_);
  runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicTransportStreamImpl::WriteOnCurrentThread,
                     base::Unretained(this), std::move(data_copy)));
}

void QuicTransportStreamImpl::Close() {
  if (stream_->CanWrite()) {
    CHECK(runner_);
    runner_->PostTaskAndReplyWithResult(
        FROM_HERE,
        base::BindOnce(&::quic::QuicTransportStream::SendFin,
                       base::Unretained(stream_)),
        base::BindOnce([](bool result) {
          DCHECK(result);
        }));
  }
}

size_t QuicTransportStreamImpl::Read(uint8_t* data, size_t length) {
  return stream_->Read(reinterpret_cast<char*>(data), length);
}

size_t QuicTransportStreamImpl::ReadableBytes() const {
  return stream_->ReadableBytes();
}

void QuicTransportStreamImpl::WriteOnCurrentThread(std::vector<uint8_t> data) {
  bool result = stream_->Write(quiche::QuicheStringPiece(
      reinterpret_cast<char*>(data.data()), data.size()));
  DCHECK(result);
}

}  // namespace quic
}  // namespace owt