/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Most classes in this file and its implementations are borrowed from
// Chromium/net/third_party/quiche/src/quic/tools/quic_simple_server_stream.cc
// with modifications.

#include "impl/web_transport_stream_impl.h"
#include "base/logging.h"
#include "base/synchronization/waitable_event.h"
#include "net/third_party/quiche/src/quic/core/web_transport_stream_adapter.h"

namespace owt {
namespace quic {

class WebTransportStreamVisitorAdapter
    : public ::quic::WebTransportStreamVisitor {
 public:
  explicit WebTransportStreamVisitorAdapter(
      ::quic::WebTransportStreamVisitor* visitor)
      : visitor_(visitor) {}

  void OnCanRead() override { visitor_->OnCanRead(); }

  void OnCanWrite() override { visitor_->OnCanWrite(); }

 private:
  ::quic::WebTransportStreamVisitor* visitor_;
};

WebTransportStreamImpl::WebTransportStreamImpl(
    ::quic::WebTransportStream* stream,
    base::SingleThreadTaskRunner* io_runner,
    base::SingleThreadTaskRunner* event_runner)
    : stream_(stream),
      io_runner_(io_runner),
      event_runner_(event_runner),
      visitor_(nullptr) {
  CHECK(stream_);
  CHECK(io_runner_);
  CHECK(event_runner_);
  stream_->SetVisitor(std::make_unique<WebTransportStreamVisitorAdapter>(this));
}

WebTransportStreamImpl::~WebTransportStreamImpl() {}

uint32_t WebTransportStreamImpl::Id() const {
  return stream_->GetStreamId();
}

size_t WebTransportStreamImpl::Write(uint8_t* data, size_t length) {
  DCHECK_EQ(sizeof(uint8_t), sizeof(char));
  CHECK(io_runner_);
  if (io_runner_->BelongsToCurrentThread()) {
    return stream_->Write(
        absl::string_view(reinterpret_cast<const char*>(data), length));
  }
  bool result;
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  io_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](WebTransportStreamImpl* stream, uint8_t* data, size_t& length,
             bool& result, base::WaitableEvent* event) {
            if (stream->stream_->CanWrite()) {
              result = stream->stream_->Write(
                  absl::string_view(reinterpret_cast<char*>(data), length));
            } else {
              result = false;
            }
            event->Signal();
          },
          base::Unretained(this), base::Unretained(data), std::ref(length),
          std::ref(result), base::Unretained(&done)));
  done.Wait();
  return result ? length : 0;
}

void WebTransportStreamImpl::SetVisitor(
    owt::quic::WebTransportStreamInterface::Visitor* visitor) {
  visitor_ = visitor;
}

size_t WebTransportStreamImpl::Read(uint8_t* data, size_t length) {
  // TODO: Post to IO runner.
  DCHECK_EQ(sizeof(uint8_t), sizeof(char));
  auto read_result = stream_->Read(reinterpret_cast<char*>(data), length);
  // TODO: FIN is not handled.
  return read_result.bytes_read;
}

size_t WebTransportStreamImpl::ReadableBytes() const {
  return stream_->ReadableBytes();
}

void WebTransportStreamImpl::Close() {
  // TODO: Post to IO runner.
  if (!stream_->SendFin()) {
    LOG(ERROR) << "Failed to send FIN.";
  }
}

uint64_t WebTransportStreamImpl::BufferedDataBytes() const {
  // TODO: Not supported.
  LOG(WARNING) << "Get buffered data bytes is not supported.";
  return 0;
}

bool WebTransportStreamImpl::CanWrite() const {
  return stream_->CanWrite();
}

void WebTransportStreamImpl::OnCanRead() {
  event_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&WebTransportStreamImpl::OnCanReadOnCurrentThread,
                     weak_factory_.GetWeakPtr()));
}

void WebTransportStreamImpl::OnCanWrite() {
  event_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&WebTransportStreamImpl::OnCanWriteOnCurrentThread,
                     weak_factory_.GetWeakPtr()));
}

void WebTransportStreamImpl::OnCanReadOnCurrentThread() {
  LOG(INFO) << "On can read.";
  if (visitor_) {
    visitor_->OnCanRead();
  }
}

void WebTransportStreamImpl::OnCanWriteOnCurrentThread() {
  if (visitor_) {
    visitor_->OnCanWrite();
  }
}

}  // namespace quic
}  // namespace owt