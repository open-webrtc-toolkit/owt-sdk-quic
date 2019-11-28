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

#ifndef OWT_QUIC_TRANSPORT_P2P_QUIC_STREAM_INTERFACE_H_
#define OWT_QUIC_TRANSPORT_P2P_QUIC_STREAM_INTERFACE_H_

#include <cstdint>
#include <vector>

namespace owt {
namespace quic {

class P2PQuicStreamInterface {
 public:
  // Some of these APIs are borrowed from
  // third_party/blink/renderer/modules/peerconnection/adapters/quic_stream_proxy.h.
  class Delegate {
   public:
    virtual ~Delegate() {}
    // Called when the remote side resets the stream.
    virtual void OnRemoteReset() {}
    // Called when the remote side receives data and/or the finish bit.
    virtual void OnDataReceived(std::vector<uint8_t> data, bool fin) {}
    // Called when data written with WriteData() has been consumed by QUIC.
    virtual void OnWriteDataConsumed(uint32_t amount) {}
  };
  virtual ~P2PQuicStreamInterface() = default;
  //virtual void Reset() = 0;
  //virtual void WriteData(std::vector<uint8_t> data, bool fin) = 0;
  //virtual void SetDelegate(Delegate* delegate) = 0;
};
}  // namespace quic
}  // namespace owt

#endif
