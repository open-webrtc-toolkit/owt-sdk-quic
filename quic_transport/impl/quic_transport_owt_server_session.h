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

#ifndef OWT_QUIC_QUIC_TRANSPORT_OWT_SERVER_SESSION_H_
#define OWT_QUIC_QUIC_TRANSPORT_OWT_SERVER_SESSION_H_

#include <memory>
#include <vector>

#include "url/origin.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_containers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_server_session.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_stream.h"

namespace owt {
namespace quic {

 // QuicTransport simple server is a non-production server that can be used for
// testing QuicTransport.  It has two modes that can be changed using the
// command line flags, "echo" and "discard".
class QuicTransportOwtServerSession
    : public ::quic::QuicTransportServerSession,
      ::quic::QuicTransportServerSession::ServerVisitor {
 public:
  QuicTransportOwtServerSession(
      ::quic::QuicConnection* connection,
      bool owns_connection,
      Visitor* owner,
      const ::quic::QuicConfig& config,
      const ::quic::ParsedQuicVersionVector& supported_versions,
      const ::quic::QuicCryptoServerConfig* crypto_config,
      ::quic::QuicCompressedCertsCache* compressed_certs_cache,
      std::vector<url::Origin> accepted_origins);
  ~QuicTransportOwtServerSession() override;

  void OnIncomingDataStream(::quic::QuicTransportStream* stream) override;
  void OnCanCreateNewOutgoingStream(bool unidirectional) override;
  bool CheckOrigin(url::Origin origin) override;
  bool ProcessPath(const GURL& url) override;
  void OnMessageReceived(quiche::QuicheStringPiece message) override;

 private:
   const bool owns_connection_;
  std::vector<url::Origin> accepted_origins_;
  ::quic::QuicCircularDeque<std::string> streams_to_echo_back_;
};


}
}

#endif