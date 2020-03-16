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

#include "impl/p2p_quic_stream_impl.h"
#include "base/bind.h"
#include "base/task_runner.h"

namespace owt {
namespace quic {
P2PQuicStreamImpl::P2PQuicStreamImpl(::quic::QuartcStream* stream,
                                     base::TaskRunner* runner)
    : quartc_stream_(stream), runner_(runner), delegate_(nullptr) {
  stream->SetDelegate(this);
}

P2PQuicStreamImpl::~P2PQuicStreamImpl() {}

size_t P2PQuicStreamImpl::OnReceived(::quic::QuartcStream* stream,
                                     iovec* iov,
                                     size_t iov_length,
                                     bool fin) {
  LOG(INFO) << "OnReceived, iov length: " << iov_length << ".";
  size_t bytes_consumed = 0;
  for (size_t i = 0; i < iov_length; ++i) {
    LOG(INFO) << "Length of a single iov: " << iov[i].iov_len << ".";
    std::vector<uint8_t> receivedData(
        static_cast<const uint8_t*>(iov[i].iov_base),
        static_cast<const uint8_t*>((uint8_t*)iov[i].iov_base +
                                    iov[i].iov_len));
    if (delegate_) {
      delegate_->OnDataReceived(receivedData,
                                 i == iov_length - 1 ? fin : false);
    }
    bytes_consumed += iov[i].iov_len;
  }
  return bytes_consumed;
}

void P2PQuicStreamImpl::OnClose(::quic::QuartcStream* stream) {
  LOG(INFO) << "OnClose.";
}

void P2PQuicStreamImpl::OnBufferChanged(::quic::QuartcStream* stream) {
  LOG(INFO) << "OnBufferChanged.";
}

void P2PQuicStreamImpl::SetDelegate(P2PQuicStreamInterface::Delegate* delegate) {
  delegate_ = delegate;
}

void P2PQuicStreamImpl::WriteOrBufferData(uint8_t* data,
                                          size_t length,
                                          bool fin) {
  CHECK(runner_);
  runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          &P2PQuicStreamImpl::WriteOrBufferDataOnCurrentThread,
          base::Unretained(this),
          quiche::QuicheStringPiece(reinterpret_cast<char*>(data), length),fin));
}

void P2PQuicStreamImpl::WriteOrBufferDataOnCurrentThread(
   quiche::QuicheStringPiece data, bool fin) {
  quartc_stream_->WriteOrBufferData(data,  fin, nullptr);
}

}  // namespace quic
}  // namespace owt