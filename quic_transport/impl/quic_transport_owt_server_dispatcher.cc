/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Most classes in this file and its implementations are borrowed from
// Chromium/net/third_party/quiche/src/quic/tools/quic_transport_simple_server_dispatcher.cc
// with modifications.

#include "impl/quic_transport_owt_server_dispatcher.h"

#include <memory>

#include "impl/quic_transport_owt_server_session.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_string_piece.h"
#include "net/third_party/quiche/src/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quic/core/quic_dispatcher.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/tools/quic_transport_simple_server_session.h"

namespace owt {
namespace quic {

using namespace ::quic;

QuicTransportOwtServerDispatcher::QuicTransportOwtServerDispatcher(
    const QuicConfig* config,
    const QuicCryptoServerConfig* crypto_config,
    QuicVersionManager* version_manager,
    std::unique_ptr<QuicConnectionHelperInterface> helper,
    std::unique_ptr<QuicCryptoServerStreamBase::Helper> session_helper,
    std::unique_ptr<QuicAlarmFactory> alarm_factory,
    uint8_t expected_server_connection_id_length,
    std::vector<url::Origin> accepted_origins,
    base::TaskRunner* task_runner,
    base::TaskRunner* event_runner)
    : QuicDispatcher(config,
                     crypto_config,
                     version_manager,
                     std::move(helper),
                     std::move(session_helper),
                     std::move(alarm_factory),
                     expected_server_connection_id_length),
      accepted_origins_(accepted_origins),
      visitor_(nullptr),
      runner_(task_runner),
      event_runner_(event_runner) {
  CHECK(runner_);
  CHECK(event_runner_);
}

QuicTransportOwtServerDispatcher::~QuicTransportOwtServerDispatcher() = default;

std::unique_ptr<QuicSession>
QuicTransportOwtServerDispatcher::CreateQuicSession(
    QuicConnectionId server_connection_id,
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address,
    quiche::QuicheStringPiece /*alpn*/,
    const ParsedQuicVersion& version) {
  auto connection = std::make_unique<QuicConnection>(
      server_connection_id, self_address, peer_address, helper(),
      alarm_factory(), writer(), /*owns_writer=*/false, Perspective::IS_SERVER,
      ParsedQuicVersionVector{version});
  auto session = std::make_unique<QuicTransportOwtServerSession>(
      connection.release(), /*owns_connection=*/true, this, config(),
      GetSupportedVersions(), crypto_config(), compressed_certs_cache(),
      accepted_origins_, runner_, event_runner_);
  session->Initialize();
  if (visitor_) {
    visitor_->OnSession(session.get());
  }
  DLOG(INFO) << "Create a new session for " << peer_address.ToString();
  return session;
}

void QuicTransportOwtServerDispatcher::SetVisitor(Visitor* visitor) {
  visitor_ = visitor;
}
}  // namespace quic
}  // namespace owt