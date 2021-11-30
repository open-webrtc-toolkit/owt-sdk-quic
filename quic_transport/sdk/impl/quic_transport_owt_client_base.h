// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A base class for the raw client, which connects to a specified port and sends
// QUIC request to that endpoint.

#ifndef QUIC_TRANSPORT_OWT_CLIENT_BASE_H_
#define QUIC_TRANSPORT_OWT_CLIENT_BASE_H_

#include <string>

#include "base/macros.h"
#include "net/third_party/quiche/src/quic/core/crypto/crypto_handshake.h"
#include "net/third_party/quiche/src/quic/core/quic_config.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/tools/quic_client_base.h"

#include "owt/quic_transport/sdk/impl/quic_transport_owt_client_session.h"

namespace quic {

class ProofVerifier;
class QuicServerId;

class QuicTransportOWTClientBase : public QuicClientBase {
 public:
  QuicTransportOWTClientBase(const QuicServerId& server_id,
                     const ParsedQuicVersionVector& supported_versions,
                     const QuicConfig& config,
                     QuicConnectionHelperInterface* helper,
                     QuicAlarmFactory* alarm_factory,
                     std::unique_ptr<NetworkHelper> network_helper,
                     std::unique_ptr<ProofVerifier> proof_verifier,
                     std::unique_ptr<SessionCache> session_cache,
                     base::SingleThreadTaskRunner* io_runner,
                     base::SingleThreadTaskRunner* event_runner);
  QuicTransportOWTClientBase(const QuicTransportOWTClientBase&) = delete;
  QuicTransportOWTClientBase& operator=(const QuicTransportOWTClientBase&) = delete;

  ~QuicTransportOWTClientBase() override;

   // QuicClientBase
  void ResendSavedData() override {}
  // If this client supports buffering data, clear it.
  void ClearDataToResend() override {}

  // A raw session has to call CryptoConnect on top of the regular
  // initialization.
  void InitializeSession() override;

  // Returns a the session used for this client downcasted to a
  // QuicRawClientSession.
  QuicTransportOWTClientSession* client_session();

 protected:
  int GetNumSentClientHellosFromSession() override;
  int GetNumReceivedServerConfigUpdatesFromSession() override;
  bool EarlyDataAccepted() override;
  bool ReceivedInchoateReject() override;
  bool HasActiveRequests() override;

  // Takes ownership of |connection|.
  std::unique_ptr<QuicSession> CreateQuicClientSession(
      const quic::ParsedQuicVersionVector& supported_versions,
      QuicConnection* connection) override;

 private:
  base::SingleThreadTaskRunner* task_runner_;
  base::SingleThreadTaskRunner* event_runner_;
};

}  // namespace quic

#endif  // NET_TOOLS_QUIC_RAW_QUIC_RAW_CLIENT_BASE_H_
