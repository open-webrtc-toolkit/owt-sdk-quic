// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "owt/quic_transport/sdk/impl/quic_transport_owt_client_base.h"

#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_random.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_logging.h"

using std::string;

namespace quic {

QuicTransportOWTClientBase::QuicTransportOWTClientBase(
    const QuicServerId& server_id,
    const ParsedQuicVersionVector& supported_versions,
    const QuicConfig& config,
    QuicConnectionHelperInterface* helper,
    QuicAlarmFactory* alarm_factory,
    std::unique_ptr<NetworkHelper> network_helper,
    std::unique_ptr<ProofVerifier> proof_verifier,
    std::unique_ptr<SessionCache> session_cache,
    base::SingleThreadTaskRunner* io_runner,
    base::SingleThreadTaskRunner* event_runner)
    : QuicClientBase(server_id,
                     supported_versions,
                     config,
                     helper,
                     alarm_factory,
                     std::move(network_helper),
                     std::move(proof_verifier),
                     std::move(session_cache)),
      task_runner_(io_runner),
      event_runner_(event_runner) {}

QuicTransportOWTClientBase::~QuicTransportOWTClientBase() {
  // If we own something. We need to explicitly kill
  // the session before something goes out of scope.
  ResetSession();
}

QuicTransportOWTClientSession* QuicTransportOWTClientBase::client_session() {
  return static_cast<QuicTransportOWTClientSession*>(QuicClientBase::session());
}

void QuicTransportOWTClientBase::InitializeSession() {
  client_session()->Initialize();
  client_session()->CryptoConnect();
}

std::unique_ptr<QuicSession> QuicTransportOWTClientBase::CreateQuicClientSession(
    const quic::ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection) {
  return std::make_unique<QuicTransportOWTClientSession>(
      connection, nullptr, *config(), supported_versions, server_id(),
      crypto_config(), task_runner_, event_runner_);
}

bool QuicTransportOWTClientBase::EarlyDataAccepted() {
  return client_session()->EarlyDataAccepted();
}

bool QuicTransportOWTClientBase::ReceivedInchoateReject() {
  return client_session()->ReceivedInchoateReject();
}

int QuicTransportOWTClientBase::GetNumSentClientHellosFromSession() {
  return client_session()->GetNumSentClientHellos();
}

int QuicTransportOWTClientBase::GetNumReceivedServerConfigUpdatesFromSession() {
  return client_session()->GetNumReceivedServerConfigUpdates();
}

bool QuicTransportOWTClientBase::HasActiveRequests() {
  return client_session()->HasActiveRequestStreams();
}

}  // namespace quic
