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
  // TODO: `data` might be destroyed before writing. Retain data until writing
  // to QuicStream.
  CHECK(runner_);
  runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicTransportStreamImpl::WriteOnCurrentThread,
                     base::Unretained(this), base::Unretained(data), length));
  // TODO: PostTaskAndReplyWithResult blocks current thread. Don't know why. Fix
  // it later.
  // runner_->PostTaskAndReplyWithResult(
  //     FROM_HERE,
  //     base::BindOnce(
  //         &::quic::QuicTransportStream::Write, base::Unretained(stream_),
  //         quiche::QuicheStringPiece(reinterpret_cast<char*>(data), length)),
  //     base::BindOnce([](bool result) { DCHECK(result); }));
}

void QuicTransportStreamImpl::Close() {
  if (stream_->CanWrite()) {
    CHECK(runner_);
    runner_->PostTaskAndReplyWithResult(
        FROM_HERE,
        base::BindOnce(&::quic::QuicTransportStream::SendFin,
                       base::Unretained(stream_)),
        base::BindOnce([](bool result) { LOG(INFO)<<"Check result";
        DCHECK(result); }));
  }
}

size_t QuicTransportStreamImpl::Read(uint8_t* data, size_t length) {
  return stream_->Read(reinterpret_cast<char*>(data), length);
}

size_t QuicTransportStreamImpl::ReadableBytes() const {
  return stream_->ReadableBytes();
}

void QuicTransportStreamImpl::WriteOnCurrentThread(uint8_t* data,
                                                   size_t length) {
  // std::cout << "Write ";
  // for (int i = 0; i < 8; i++) {
  //   std::cout << (unsigned int)data[i] << " ";
  // }
  // std::cout<<std::endl;
  stream_->WriteOrBufferData(
      quiche::QuicheStringPiece(reinterpret_cast<char*>(data), length), false,
      nullptr);
  // bool result = stream_->Write(
  //     quiche::QuicheStringPiece(reinterpret_cast<char*>(data), length));
  // DCHECK(result);
}

}  // namespace quic
}  // namespace owt