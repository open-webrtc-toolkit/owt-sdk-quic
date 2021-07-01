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

#include "owt/quic/export.h"
#include <cstdint>

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
// Ref: net/third_party/quiche/src/quic/quic_transport/web_transport_fingerprint_proof_verifier.h
struct OWT_EXPORT CertificateFingerprint{
  const char* fingerprint;
};

}  // namespace quic
}  // namespace owt

#endif