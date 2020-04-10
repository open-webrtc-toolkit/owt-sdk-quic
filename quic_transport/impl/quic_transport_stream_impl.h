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
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_stream.h"
#include "owt/quic/quic_transport_stream_interface.h"

namespace owt {
namespace quic {
class QuicTransportStreamImpl : public QuicTransportStreamInterface,
                                public ::quic::QuicTransportStream::Visitor {
 public:
  explicit QuicTransportStreamImpl(::quic::QuicTransportStream* stream,
                                   base::TaskRunner* runner);
  ~QuicTransportStreamImpl() override;

  // Overrides QuicTransportStreamInterface.
  void SetVisitor(
      owt::quic::QuicTransportStreamInterface::Visitor* visitor) override;
  void Write(uint8_t* data, size_t length) override;
  void Close() override;

  // Overrides ::quic::QuicTransportStream::Visitor.
  void OnCanRead() override;
  void OnFinRead() override;
  void OnCanWrite() override;

 protected:
  ::quic::QuicTransportStream* stream_;
  base::TaskRunner* runner_;
  owt::quic::QuicTransportStreamInterface::Visitor* visitor_;
};
}  // namespace quic
}  // namespace owt

#endif