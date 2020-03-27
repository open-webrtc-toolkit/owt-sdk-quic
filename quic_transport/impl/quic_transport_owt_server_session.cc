/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Most classes in this file and its implementations are borrowed from
// Chromium/net/third_party/quiche/src/quic/tools/quic_transport_simple_server_session.cc
// with modifications.
#include "impl/quic_transport_owt_server_session.h"

#include <memory>

#include "url/gurl.h"
#include "url/origin.h"
#include "net/third_party/quiche/src/quic/core/quic_buffer_allocator.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_protocol.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_stream.h"

namespace owt {
namespace quic {
QuicTransportOwtServerSession::QuicTransportOwtServerSession(
      ::quic::QuicConnection* connection,
      bool owns_connection,
      Visitor* owner,
      const ::quic::QuicConfig& config,
      const ::quic::ParsedQuicVersionVector& supported_versions,
      const ::quic::QuicCryptoServerConfig* crypto_config,
      ::quic::QuicCompressedCertsCache* compressed_certs_cache,
      std::vector<url::Origin> accepted_origins)
    : QuicTransportServerSession(connection,
                                 owner,
                                 config,
                                 supported_versions,
                                 crypto_config,
                                 compressed_certs_cache,
                                 this),
      owns_connection_(owns_connection),
      accepted_origins_(accepted_origins) {}

QuicTransportOwtServerSession::~QuicTransportOwtServerSession() {
  if (owns_connection_) {
    DeleteConnection();
  }
}

void QuicTransportOwtServerSession::OnIncomingDataStream(
    ::quic::QuicTransportStream* stream) {
}

void QuicTransportOwtServerSession::OnCanCreateNewOutgoingStream(
    bool unidirectional) {
}

bool QuicTransportOwtServerSession::CheckOrigin(url::Origin origin) {
  if (accepted_origins_.empty()) {
    return true;
  }

  for (const url::Origin& accepted_origin : accepted_origins_) {
    if (origin.IsSameOriginWith(accepted_origin)) {
      return true;
    }
  }
  return false;
}

bool QuicTransportOwtServerSession::ProcessPath(const GURL& url) {
  if (url.path() == "/echo"||url.path()=="/") {
    return true;
  }

  QUIC_DLOG(WARNING) << "Unknown path requested: " << url.path();
  return false;
}

void QuicTransportOwtServerSession::OnMessageReceived(
    quiche::QuicheStringPiece message) {
}
}  // namespace quic
}  // namespace owt
