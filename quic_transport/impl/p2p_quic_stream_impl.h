/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Most classes in this file and its implementations are borrowed from
// Chromium/src/third_party/blink/renderer/modules/peerconnection/adapters/*
// with modifications.

#include "net/third_party/quiche/src/quic/quartc/quartc_stream.h"
#include "owt/quic/p2p_quic_stream.h"

namespace base {
class TaskRunner;
}

namespace owt {
namespace quic {
class P2PQuicStreamImpl : public ::quic::QuartcStream::Delegate {
 public:
  explicit P2PQuicStreamImpl(::quic::QuartcStream* stream,
                             base::TaskRunner* runner);
  ~P2PQuicStreamImpl() override;
  void SetDelegate(P2PQuicStream::Delegate* delegate);
  void WriteOrBufferData(::quic::QuicStringPiece data, bool fin);
  void WriteOrBufferData(std::vector<uint8_t> data, bool fin);

 protected:
  // Implements quic::QuartcStream::Delegate.
  size_t OnReceived(::quic::QuartcStream* stream,
                    iovec* iov,
                    size_t iov_length,
                    bool fin) override;
  void OnClose(::quic::QuartcStream* stream) override;
  void OnBufferChanged(::quic::QuartcStream* stream) override;

 private:
  void WriteOrBufferDataOnCurrentThread(std::vector<uint8_t> data, bool fin);
  ::quic::QuartcStream* m_quartcStream;
  base::TaskRunner* m_runner;
  P2PQuicStream::Delegate* m_delegate;
  std::queue<std::vector<uint8_t>> m_receivedBuffer;
};
}  // namespace quic
}  // namespace owt