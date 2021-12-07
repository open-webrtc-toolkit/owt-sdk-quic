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

#include "impl/web_transport_owt_server_dispatcher.h"
#include <memory>
#include "impl/http3_server_session.h"
#include "net/third_party/quiche/src/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quic/core/quic_dispatcher.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"

namespace owt {
namespace quic {

using namespace ::quic;

WebTransportOwtServerDispatcher::WebTransportOwtServerDispatcher(
    const QuicConfig* config,
    const QuicCryptoServerConfig* crypto_config,
    QuicVersionManager* version_manager,
    std::unique_ptr<QuicConnectionHelperInterface> helper,
    std::unique_ptr<QuicCryptoServerStreamBase::Helper> session_helper,
    std::unique_ptr<QuicAlarmFactory> alarm_factory,
    uint8_t expected_server_connection_id_length,
    std::vector<url::Origin> accepted_origins,
    WebTransportServerBackend* backend,
    base::SingleThreadTaskRunner* task_runner,
    base::SingleThreadTaskRunner* event_runner)
    : QuicDispatcher(config,
                     crypto_config,
                     version_manager,
                     std::move(helper),
                     std::move(session_helper),
                     std::move(alarm_factory),
                     expected_server_connection_id_length),
      accepted_origins_(accepted_origins),
      visitor_(nullptr),
      backend_(backend),
      runner_(task_runner),
      event_runner_(event_runner) {
  CHECK(backend_);
  CHECK(runner_);
  CHECK(event_runner_);
}

WebTransportOwtServerDispatcher::~WebTransportOwtServerDispatcher() = default;

std::unique_ptr<QuicSession> WebTransportOwtServerDispatcher::CreateQuicSession(
    QuicConnectionId server_connection_id,
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address,
    absl::string_view /*alpn*/,
    const ParsedQuicVersion& version,
    const ParsedClientHello& /*parsed_chlo*/) {
  auto connection = std::make_unique<QuicConnection>(
      server_connection_id, self_address, peer_address, helper(),
      alarm_factory(), writer(), /*owns_writer=*/false, Perspective::IS_SERVER,
      ParsedQuicVersionVector{version});
  auto session = std::make_unique<Http3ServerSession>(
      config(), GetSupportedVersions(), connection.release(), this,
      session_helper(), crypto_config(), compressed_certs_cache(), backend_,
      runner_, event_runner_);
  session->Initialize();
  DLOG(INFO) << "Create a new session for " << peer_address.ToString();
  return session;
}

void WebTransportOwtServerDispatcher::SetVisitor(Visitor* visitor) {
  visitor_ = visitor;
}
}  // namespace quic
}  // namespace owt