// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "owt/quic_transport/sdk/impl/quic_transport_owt_dispatcher.h"

namespace quic {

QuicTransportOWTDispatcher::QuicTransportOWTDispatcher(
    const QuicConfig* config,
    const QuicCryptoServerConfig* crypto_config,
    QuicVersionManager* version_manager,
    std::unique_ptr<QuicConnectionHelperInterface> helper,
    std::unique_ptr<QuicCryptoServerStream::Helper> session_helper,
    std::unique_ptr<QuicAlarmFactory> alarm_factory,
    uint8_t expected_server_connection_id_length,
    base::SingleThreadTaskRunner* io_runner,
    base::SingleThreadTaskRunner* event_runner)
    : QuicDispatcher(config,
                     crypto_config,
                     version_manager,
                     std::move(helper),
                     std::move(session_helper),
                     std::move(alarm_factory),
                     expected_server_connection_id_length),
      task_runner_(io_runner),
      event_runner_(event_runner),
      visitor_(nullptr){}

QuicTransportOWTDispatcher::~QuicTransportOWTDispatcher() = default;


std::unique_ptr<QuicSession> QuicTransportOWTDispatcher::CreateQuicSession(
    QuicConnectionId connection_id,
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address,
    absl::string_view /*alpn*/,
    const ParsedQuicVersion& version,
    absl::string_view /*sni*/) {
  // The QuicServerSessionBase takes ownership of |connection| below.
    printf("QuicTransportOWTDispatcher::CreateQuicSession in thread:%d\n", base::PlatformThread::CurrentId());
  QuicConnection* connection = 
      new QuicConnection(connection_id, self_address, peer_address, helper(),
                         alarm_factory(), writer(),
                         /* owns_writer= */ false, Perspective::IS_SERVER,
                         ParsedQuicVersionVector{version});

  auto session = std::make_unique<QuicTransportOWTServerSession>(
      connection, this, config(), GetSupportedVersions(), session_helper(),
      crypto_config(), compressed_certs_cache(), task_runner_, event_runner_);
  session->Initialize();
  if (visitor_) {
    printf("QuicTransportOWTDispatcher call visitor OnSessionCreated\n");
    visitor_->OnSessionCreated(session.get());
  }
  return session;
}

// Called when the connection is closed after the streams have been closed.
  void QuicTransportOWTDispatcher::OnConnectionClosed(QuicConnectionId server_connection_id,
                                    QuicErrorCode error,
                                    const std::string& error_details,
                                    ConnectionCloseSource source) {
    printf("QuicTransportOWTDispatcher OnConnectionClosed for connection:%s in thread:%d\n", server_connection_id.ToString().c_str(), base::PlatformThread::CurrentId());
    if (visitor_) {
      visitor_->OnSessionClosed(server_connection_id);
    }

    printf("QuicTransportOWTDispatcher OnConnectionClosed ends\n");
  }

}  // namespace quic
