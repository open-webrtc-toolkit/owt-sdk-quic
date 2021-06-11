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

#ifndef OWT_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_OWT_SERVER_SESSION_H_
#define OWT_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_OWT_SERVER_SESSION_H_

#include <memory>
#include <vector>

#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_containers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_server_session.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_stream.h"
#include "owt/quic/quic_transport_session_interface.h"
#include "owt/web_transport/sdk/impl/quic_transport_stream_impl.h"
#include "url/origin.h"

namespace owt {
namespace quic {

class QuicTransportOwtServerSession
    : public QuicTransportSessionInterface,
      public ::quic::QuicTransportServerSession,
      ::quic::QuicTransportServerSession::ServerVisitor {
 public:
  QuicTransportOwtServerSession(
      ::quic::QuicConnection* connection,
      bool owns_connection,
      QuicSession::Visitor* owner,
      const ::quic::QuicConfig& config,
      const ::quic::ParsedQuicVersionVector& supported_versions,
      const ::quic::QuicCryptoServerConfig* crypto_config,
      ::quic::QuicCompressedCertsCache* compressed_certs_cache,
      std::vector<url::Origin> accepted_origins,
      base::SingleThreadTaskRunner* runner,
      base::SingleThreadTaskRunner* event_runner);
  ~QuicTransportOwtServerSession() override;

  // Override QuicTransportSessionInterface.
  void SetVisitor(
      owt::quic::QuicTransportSessionInterface::Visitor* visitor) override;
  // Caller needs to free the connection ID returned.
  const char* ConnectionId() const override;
  bool IsSessionReady() const override;
  QuicTransportStreamInterface* CreateBidirectionalStream() override;
  const ConnectionStats& GetStats() override;

  void OnConnectionClosed(const ::quic::QuicConnectionCloseFrame& frame,
                          ::quic::ConnectionCloseSource source) override;

 protected:
  void OnIncomingDataStream(::quic::QuicTransportStream* stream) override;
  void OnCanCreateNewOutgoingStream(bool unidirectional) override;
  bool CheckOrigin(url::Origin origin) override;
  bool ProcessPath(const GURL& url) override;
  void OnMessageReceived(absl::string_view message) override;

 private:
  QuicTransportStreamInterface* CreateBidirectionalStreamOnCurrentThread();

  const bool owns_connection_;
  std::vector<url::Origin> accepted_origins_;
  owt::quic::QuicTransportSessionInterface::Visitor* visitor_;
  std::vector<std::unique_ptr<QuicTransportStreamImpl>> streams_;
  base::SingleThreadTaskRunner* runner_;
  base::SingleThreadTaskRunner* event_runner_;
  ConnectionStats stats_;
  base::WeakPtrFactory<QuicTransportOwtServerSession> weak_factory_{this};
};

}  // namespace quic
}  // namespace owt

#endif