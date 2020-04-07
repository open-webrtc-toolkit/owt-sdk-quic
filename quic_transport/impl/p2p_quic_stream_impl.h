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

#ifndef OWT_QUIC_QUIC_TRANSPORT_P2P_QUIC_STREAM_IMPL_H_
#define OWT_QUIC_QUIC_TRANSPORT_P2P_QUIC_STREAM_IMPL_H_

#include "net/third_party/quiche/src/quic/quartc/quartc_stream.h"
#include "owt/quic/p2p_quic_stream_interface.h"

namespace base {
class TaskRunner;
}

namespace owt {
namespace quic {
class P2PQuicStreamImpl : public P2PQuicStreamInterface,
                          public ::quic::QuartcStream::Delegate {
 public:
  explicit P2PQuicStreamImpl(::quic::QuartcStream* stream,
                             base::TaskRunner* runner);
  ~P2PQuicStreamImpl() override;
  void SetDelegate(P2PQuicStreamInterface::Delegate* delegate) override;
  void WriteOrBufferData(uint8_t* data, size_t length, bool fin) override;

 protected:
  // Implements quic::QuartcStream::Delegate.
  size_t OnReceived(::quic::QuartcStream* stream,
                    iovec* iov,
                    size_t iov_length,
                    bool fin) override;
  void OnClose(::quic::QuartcStream* stream) override;
  void OnBufferChanged(::quic::QuartcStream* stream) override;

 private:
  void WriteOrBufferDataOnCurrentThread(quiche::QuicheStringPiece data, bool fin);
  ::quic::QuartcStream* quartc_stream_;
  base::TaskRunner* runner_;
  P2PQuicStreamInterface::Delegate* delegate_;
  std::queue<std::vector<uint8_t>> received_buffer_;
};
}  // namespace quic
}  // namespace owt

#endif