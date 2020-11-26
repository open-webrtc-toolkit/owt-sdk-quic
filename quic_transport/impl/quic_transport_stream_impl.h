/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Most classes in this file and its implementations are borrowed from
// Chromium/net/third_party/quiche/src/quic/tools/quic_transport_simple_server_session.h
// with modifications.

#ifndef OWT_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_STREAM_IMPL_H_
#define OWT_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_STREAM_IMPL_H_

#include "base/memory/weak_ptr.h"
#include "base/task_runner.h"
#include "base/threading/thread_checker.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_stream.h"
#include "owt/quic/quic_transport_stream_interface.h"

namespace owt {
namespace quic {

// QuicTransportStreamImpl is a proxy for ::quic::QuicTransportStream. All calls
// to ::quic::QuicTransportStream run in runner_.
class QuicTransportStreamImpl : public QuicTransportStreamInterface,
                                public ::quic::QuicTransportStream::Visitor {
 public:
  explicit QuicTransportStreamImpl(::quic::QuicTransportStream* stream,
                                   base::TaskRunner* runner);
  ~QuicTransportStreamImpl() override;

  // Overrides QuicTransportStreamInterface.
  void SetVisitor(
      owt::quic::QuicTransportStreamInterface::Visitor* visitor) override;
  uint32_t Id() const override;
  size_t Write(uint8_t* data, size_t length) override;
  size_t Read(uint8_t* data, size_t length) override;
  size_t ReadableBytes() const override;
  void Close() override;
  uint64_t BufferedDataBytes() const override;

  // Overrides ::quic::QuicTransportStream::Visitor.
  void OnCanRead() override;
  void OnFinRead() override;
  void OnCanWrite() override;

 protected:
  ::quic::QuicTransportStream* stream_;
  base::TaskRunner* runner_;
  owt::quic::QuicTransportStreamInterface::Visitor* visitor_;
  base::ThreadChecker thread_checker_;

 private:
  void WriteOnCurrentThread(std::vector<uint8_t> data);
};
}  // namespace quic
}  // namespace owt

#endif