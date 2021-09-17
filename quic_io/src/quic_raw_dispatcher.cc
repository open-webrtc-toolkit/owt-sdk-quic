// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/raw/quic_raw_dispatcher.h"


namespace quic {

QuicRawDispatcher::QuicRawDispatcher(
    const QuicConfig* config,
    const QuicCryptoServerConfig* crypto_config,
    QuicVersionManager* version_manager,
    std::unique_ptr<QuicConnectionHelperInterface> helper,
    std::unique_ptr<QuicCryptoServerStream::Helper> session_helper,
    std::unique_ptr<QuicAlarmFactory> alarm_factory,
    uint8_t expected_server_connection_id_length)
    : QuicDispatcher(config,
                     crypto_config,
                     version_manager,
                     std::move(helper),
                     std::move(session_helper),
                     std::move(alarm_factory),
                     expected_server_connection_id_length),
      visitor_(nullptr){}

QuicRawDispatcher::~QuicRawDispatcher() = default;


std::unique_ptr<QuicSession> QuicRawDispatcher::CreateQuicSession(
    QuicConnectionId connection_id,
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address,
    absl::string_view /*alpn*/,
    const ParsedQuicVersion& version,
    absl::string_view /*sni*/) {
  // The QuicServerSessionBase takes ownership of |connection| below.
  QuicConnection* connection = 
      new QuicConnection(connection_id, self_address, peer_address, helper(),
                         alarm_factory(), writer(),
                         /* owns_writer= */ false, Perspective::IS_SERVER,
                         ParsedQuicVersionVector{version});

  auto session = std::make_unique<QuicRawServerSession>(
      connection, this, config(), GetSupportedVersions(), session_helper(),
      crypto_config(), compressed_certs_cache());
  session->Initialize();
  if (visitor_) {
    visitor_->OnSessionCreated(session.get());
  }
  return session;
}

}  // namespace quic
