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

#ifndef OWT_WEB_TRANSPORT_WEB_TRANSPORT_QUIC_TRANSPORT_STREAM_IMPL_H_
#define OWT_WEB_TRANSPORT_WEB_TRANSPORT_QUIC_TRANSPORT_STREAM_IMPL_H_

#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_checker.h"
#include "net/third_party/quiche/src/quic/core/web_transport_interface.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_stream.h"
#include "owt/quic/web_transport_stream_interface.h"

namespace owt {
namespace quic {

// QuicTransportStreamImpl is a proxy for ::quic::QuicTransportStream. All calls
// to ::quic::QuicTransportStream run in runner_.
class QuicTransportStreamImpl : public WebTransportStreamInterface,
                                public ::quic::WebTransportStreamVisitor {
 public:
  explicit QuicTransportStreamImpl(::quic::QuicTransportStream* stream,
                                   base::SingleThreadTaskRunner* runner,
                                   base::SingleThreadTaskRunner* event_runner);
  ~QuicTransportStreamImpl() override;

  // Overrides WebTransportStreamInterface.
  void SetVisitor(
      owt::quic::WebTransportStreamInterface::Visitor* visitor) override;
  uint32_t Id() const override;
  size_t Write(uint8_t* data, size_t length) override;
  size_t Read(uint8_t* data, size_t length) override;
  size_t ReadableBytes() const override;
  void Close() override;
  uint64_t BufferedDataBytes() const override;
  bool CanWrite() const override;

  // Overrides ::quic::WebTransportStreamVisitor.
  void OnCanRead() override;
  void OnCanWrite() override;

 protected:
  ::quic::QuicTransportStream* stream_;
  base::SingleThreadTaskRunner* io_runner_;
  base::SingleThreadTaskRunner* event_runner_;
  owt::quic::WebTransportStreamInterface::Visitor* visitor_;

 private:
  void WriteOnCurrentThread(std::vector<uint8_t> data);

  void OnCanReadOnCurrentThread();
  void OnFinReadOnCurrentThread();
  void OnCanWriteOnCurrentThread();

  base::WeakPtrFactory<QuicTransportStreamImpl> weak_factory_{this};
};
}  // namespace quic
}  // namespace owt

#endif