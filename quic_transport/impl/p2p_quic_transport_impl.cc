/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "impl/p2p_quic_transport_impl.h"
#include "impl/quic_packet_transport_ice_adapter.h"
#include "net/quic/platform/impl/quic_chromium_clock.cc"
#include "net/third_party/quiche/src/quic/core/crypto/proof_verifier.h"
#include "net/third_party/quiche/src/quic/core/quic_connection_id.h"
#include "net/third_party/quiche/src/quic/core/quic_crypto_client_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_crypto_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/core/tls_client_handshaker.h"
#include "net/third_party/quiche/src/quic/quartc/quartc_crypto_helpers.h"
#include "owt/quic/ice_transport_interface.h"
#include "owt/quic/p2p_quic_stream_interface.h"
#include "owt/quic/p2p_quic_transport_interface.h"
#include "third_party/blink/renderer/modules/peerconnection/adapters/p2p_quic_crypto_config_factory_impl.h"
#include "third_party/webrtc/rtc_base/ssl_certificate.h"

namespace owt {
namespace quic {

P2PQuicTransportImpl::P2PQuicTransportImpl(
    std::weak_ptr<IceTransportInterface> ice_transport,
    const ::quic::QuicConfig& quic_config,
    const ::quic::QuicCryptoServerConfig* crypto_config,
    ::quic::QuicCompressedCertsCache* const compressed_certs_cache,
    ::quic::QuicClock* clock,
    ::quic::QuicAlarmFactory* alarm_factory,
    ::quic::QuicConnectionHelperInterface* connection_helper,
    base::TaskRunner* runner) {
  quartc_packet_transport_ =
      std::make_unique<QuicPacketTransportIceAdapter>(ice_transport, runner);
  quartc_packet_writer_ = std::make_unique<::quic::QuartcPacketWriter>(
      quartc_packet_transport_.get(), 1200);
  char connection_id_bytes[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  ::quic::QuicConnectionId dummy_id = ::quic::QuicConnectionId(
      connection_id_bytes, sizeof(connection_id_bytes));
  ::quic::QuicSocketAddress dummy_address(::quic::QuicIpAddress::Any4(),
                                          /*port=*/0);
  std::unique_ptr<::quic::QuicConnection> quic_connection =
      ::quic::CreateQuicConnection(dummy_id, dummy_address, connection_helper,
                                   alarm_factory, quartc_packet_writer_.get(),
                                   ::quic::Perspective::IS_SERVER,
                                   ::quic::CurrentSupportedVersions());
  quartc_session_ = std::make_unique<::quic::QuartcServerSession>(
      std::move(quic_connection), nullptr, quic_config,
      ::quic::CurrentSupportedVersions(), clock, crypto_config,
      compressed_certs_cache, new ::quic::QuartcCryptoServerStreamHelper());
}

// P2PQuicTransportImpl::P2PQuicTransportImpl(
//     std::unique_ptr<::quic::QuicConnection> connection,
//     const ::quic::QuicConfig& config,
//     ::quic::QuicClock* clock,
//     std::shared_ptr<::quic::QuartcPacketWriter> packetWriter,
//     std::shared_ptr<::quic::QuicCryptoServerConfig> cryptoServerConfig,
//     ::quic::QuicCompressedCertsCache* const compressedCertsCache,
//     base::TaskRunner* runner)
//     : ::quic::QuartcServerSession(
//           std::move(connection),
//           nullptr,
//           config,
//           ::quic::CurrentSupportedVersions(),
//           clock,
//           cryptoServerConfig.get(),
//           compressedCertsCache,
//           new ::quic::QuartcCryptoServerStreamHelper()) {
//   m_writer = packetWriter;
//   m_cryptoServerConfig = cryptoServerConfig;
//   m_delegate = nullptr;
//   m_runner = runner;
// }

std::unique_ptr<P2PQuicTransportImpl> P2PQuicTransportImpl::Create(
    const ::quic::QuartcSessionConfig& quartcSessionConfig,
    ::quic::Perspective perspective,
    std::shared_ptr<::quic::QuartcPacketTransport> transport,
    ::quic::QuicClock* clock,
    std::shared_ptr<::quic::QuicAlarmFactory> alarmFactory,
    std::shared_ptr<::quic::QuicConnectionHelperInterface> helper,
    std::shared_ptr<::quic::QuicCryptoServerConfig> cryptoServerConfig,
    ::quic::QuicCompressedCertsCache* const compressedCertsCache,
    base::TaskRunner* runner) {
  LOG(INFO) << "Create ::quic::QuartcPacketWriter.";
  auto writer = std::make_shared<::quic::QuartcPacketWriter>(
      transport.get(), quartcSessionConfig.max_packet_size);
  ::quic::QuicConfig quicConfig = ::quic::CreateQuicConfig(quartcSessionConfig);
  LOG(INFO) << "Create QUIC connection.";
  std::unique_ptr<::quic::QuicConnection> quicConnection =
      CreateQuicConnection(perspective, writer, alarmFactory, helper);
  return std::make_unique<P2PQuicTransportImpl>(
      std::move(quicConnection), quicConfig, clock, writer, cryptoServerConfig,
      compressedCertsCache, runner);
}
std::unique_ptr<::quic::QuicConnection>
P2PQuicTransportImpl::CreateQuicConnection(
    ::quic::Perspective perspective,
    std::shared_ptr<::quic::QuartcPacketWriter> writer,
    std::shared_ptr<::quic::QuicAlarmFactory> alarmFactory,
    std::shared_ptr<::quic::QuicConnectionHelperInterface> connectionHelper) {
  LOG(INFO) << "P2PQuicTransportImpl::createQuicConnection";
  // Copied from net/third_party/quiche/src/quic/quartc/quartc_factory.cc.
  // |dummyId| and |dummyAddress| are used because Quartc network layer will
  // not use these two.
  ::quic::QuicConnectionId dummyId;
  char connectionIdBytes[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  dummyId =
      ::quic::QuicConnectionId(connectionIdBytes, sizeof(connectionIdBytes));
  ::quic::QuicSocketAddress dummyAddress(::quic::QuicIpAddress::Any4(),
                                         /*port=*/0);
  return ::quic::CreateQuicConnection(
      dummyId, dummyAddress, connectionHelper.get(), alarmFactory.get(),
      writer.get(), perspective, ::quic::CurrentSupportedVersions());
}

std::vector<rtc::scoped_refptr<rtc::RTCCertificate>>
P2PQuicTransportImpl::GetCertificates() const {
  return std::vector<rtc::scoped_refptr<rtc::RTCCertificate>>();
}

void P2PQuicTransportImpl::Start(
    std::unique_ptr<RTCQuicParameters> remoteParameters) {
  LOG(INFO) << "P2PQuicTransportImpl::start.";
  quartc_session_->StartCryptoHandshake();
  quartc_session_->Initialize();
  LOG(INFO) << "After start crypto handshake.";
}

RTCQuicParameters P2PQuicTransportImpl::GetLocalParameters() const {
  return RTCQuicParameters();
}

// void P2PQuicTransportImpl::OnConnectionClosed(
//     const ::quic::QuicConnectionCloseFrame& frame,
//     ::quic::ConnectionCloseSource source) {
//   LOG(INFO) << "P2PQuicTransportImpl::OnConnectionClosed";
// }

// void P2PQuicTransportImpl::OnMessageReceived(::quic::QuicStringPiece message)
// {
//   LOG(INFO) << "P2PQuicTransportImpl::OnMessageReceived";
// }

// // void P2PQuicTransportImpl::OnMessageSent(int64_t datagram_id) {
// //   LOG(INFO) << "P2PQuicTransportImpl::OnMessageSent";
// // }

// void P2PQuicTransportImpl::OnMessageAcked(::quic::QuicMessageId message_id,
//                                           ::quic::QuicTime receive_timestamp)
//                                           {
//   LOG(INFO) << "P2PQuicTransportImpl::OnMessageAcked";
// }

// void P2PQuicTransportImpl::OnMessageLost(::quic::QuicMessageId message_id) {
//   LOG(INFO) << "P2PQuicTransportImpl::OnMessageLost";
// }

P2PQuicTransportImpl::~P2PQuicTransportImpl() {
  LOG(INFO) << "~P2PQuicTransportImpl";
}
}  // namespace quic
}  // namespace owt