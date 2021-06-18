/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Most classes in this file and its implementations are borrowed from
// Chromium/net/third_party/quiche/src/quic/tools/quic_simple_server_stream.h
// with modifications.

#ifndef OWT_QUIC_WEB_TRANSPORT_WEB_TRANSPORT_SERVER_STREAM_H_
#define OWT_QUIC_WEB_TRANSPORT_WEB_TRANSPORT_SERVER_STREAM_H_

#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_checker.h"
#include "impl/http3_server_stream.h"
#include "net/third_party/quiche/src/quic/core/http/quic_spdy_stream.h"
#include "net/third_party/quiche/src/quic/core/web_transport_interface.h"
#include "owt/quic/web_transport_stream_interface.h"

namespace owt {
namespace quic {

// WebTransportServerStream is a proxy for ::quic::WebTransportStream. All calls
// to ::quic::WebTransportStream run in runner_.
class WebTransportServerStream : public WebTransportStreamInterface,
                                 public ::quic::WebTransportStreamVisitor {
 public:
  explicit WebTransportServerStream(::quic::WebTransportStream* stream,
                                    base::SingleThreadTaskRunner* io_runner,
                                    base::SingleThreadTaskRunner* event_runner);
  ~WebTransportServerStream() override;

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

 private:
  void WriteOnCurrentThread(std::vector<uint8_t> data);

  void OnCanReadOnCurrentThread();
  void OnFinReadOnCurrentThread();
  void OnCanWriteOnCurrentThread();

  ::quic::WebTransportStream* stream_;
  base::SingleThreadTaskRunner* io_runner_;
  base::SingleThreadTaskRunner* event_runner_;
  owt::quic::WebTransportStreamInterface::Visitor* visitor_;
  base::WeakPtrFactory<WebTransportServerStream> weak_factory_{this};
};
}  // namespace quic
}  // namespace owt

#endif