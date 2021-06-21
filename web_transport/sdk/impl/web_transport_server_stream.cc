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

#include "impl/web_transport_server_stream.h"
#include "base/logging.h"
#include "base/synchronization/waitable_event.h"

namespace owt {
namespace quic {

WebTransportServerStream::WebTransportServerStream(
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
}

WebTransportServerStream::~WebTransportServerStream() {}

uint32_t WebTransportServerStream::Id() const {
  return stream_->GetStreamId();
}

size_t WebTransportServerStream::Write(uint8_t* data, size_t length) {
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
          [](WebTransportServerStream* stream, uint8_t* data, size_t& length,
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

void WebTransportServerStream::SetVisitor(
    owt::quic::WebTransportStreamInterface::Visitor* visitor) {
  visitor_ = visitor;
}

size_t WebTransportServerStream::Read(uint8_t* data, size_t length) {
  // TODO: Post to IO runner.
  DCHECK_EQ(sizeof(uint8_t), sizeof(char));
  auto read_result = stream_->Read(reinterpret_cast<char*>(data), length);
  // TODO: FIN is not handled.
  return read_result.bytes_read;
}

size_t WebTransportServerStream::ReadableBytes() const {
  return stream_->ReadableBytes();
}

void WebTransportServerStream::Close() {
  // TODO: Post to IO runner.
  if (!stream_->SendFin()) {
    LOG(ERROR) << "Failed to send FIN.";
  }
}

uint64_t WebTransportServerStream::BufferedDataBytes() const {
  // TODO: Not supported.
  LOG(WARNING) << "Get buffered data bytes is not supported.";
  return 0;
}

bool WebTransportServerStream::CanWrite() const {
  return stream_->CanWrite();
}

void WebTransportServerStream::OnCanRead() {
  event_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&WebTransportServerStream::OnCanReadOnCurrentThread,
                     weak_factory_.GetWeakPtr()));
}

void WebTransportServerStream::OnCanWrite() {
  event_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&WebTransportServerStream::OnCanWriteOnCurrentThread,
                     weak_factory_.GetWeakPtr()));
}

void WebTransportServerStream::OnCanReadOnCurrentThread() {
  if (visitor_) {
    visitor_->OnCanRead();
  }
}

void WebTransportServerStream::OnCanWriteOnCurrentThread() {
  if (visitor_) {
    visitor_->OnCanWrite();
  }
}

}  // namespace quic
}  // namespace owt