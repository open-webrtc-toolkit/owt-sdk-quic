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

#ifndef OWT_QUIC_TRANSPORT_P2P_QUIC_TRANSPORT_INTERFACE_H_
#define OWT_QUIC_TRANSPORT_P2P_QUIC_TRANSPORT_INTERFACE_H_

#include "quic_definitions.h"
#include "export.h"

namespace owt {
namespace quic {
class P2PQuicStreamInterface;
class OWT_EXPORT P2PQuicTransportInterface {
 public:
  // Delegate for receiving callbacks from the QUIC transport.
  class Delegate {
   public:
    // Called when the remote side has created a new stream.
    virtual void OnStream(P2PQuicStreamInterface* stream) {}
  };
  virtual ~P2PQuicTransportInterface() = default;
  virtual RTCQuicParameters GetLocalParameters() const = 0;
  virtual void Listen(const std::string& remote_key) = 0;
  virtual void Listen(uint8_t* key, size_t length) = 0;
  // virtual void Stop() = 0;
  // virtual void Start() = 0;
  // virtual P2PQuicStream* CreateStream() = 0;
};
}  // namespace quic
}  // namespace owt

#endif