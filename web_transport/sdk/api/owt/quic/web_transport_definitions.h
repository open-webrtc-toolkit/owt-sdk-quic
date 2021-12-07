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

#ifndef OWT_WEB_TRANSPORT_WEB_TRANSPORT_DEFINITIONS_H_
#define OWT_WEB_TRANSPORT_WEB_TRANSPORT_DEFINITIONS_H_

#include <cstdint>
#include "owt/quic/export.h"

namespace owt {
namespace quic {

// Stats for a QUIC connection.
// Ref: net/third_party/quiche/src/quic/core/quic_connection_stats.h.
struct OWT_EXPORT ConnectionStats {
  // Estimated bandwidth in bit per second.
  uint64_t estimated_bandwidth;
};

// Hash function algorithm and certificate fingerprint as described in RFC4572.
// Algorithm is always sha-256 at this moment.
// Ref: https://w3c.github.io/webrtc-pc/#dom-rtcdtlsfingerprint
// Ref:
// net/third_party/quiche/src/quic/quic_transport/web_transport_fingerprint_proof_verifier.h
struct OWT_EXPORT CertificateFingerprint {
  const char* fingerprint;
};

// Status of message being sent.
// 1:1 mapping to MessageStatus in
// net/third_party/quiche/src/quic/core/quic_types.h except kUnavailable.
enum class MessageStatus {
  // Success.
  kSuccess,
  // Failed to send message because encryption is not established yet.
  kEncryptionNotEstablished,
  // Failed to send message because MESSAGE frame is not supported by the
  // connection.
  kUnsupported,
  // Failed to send message because connection is congestion control blocked or
  // underlying socket is write blocked.
  kBlocked,
  // Failed to send message because the message is too large to fit into a
  // single packet.
  kTooLarge,
  // Failed to send message because connection reaches an invalid state.
  kInternalError,
  // Message status is not available. When C++17 std::optional is enabled, this
  // value will be removed.
  kUnavailable
};

}  // namespace quic
}  // namespace owt

#endif