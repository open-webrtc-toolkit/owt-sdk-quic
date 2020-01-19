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
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/third_party/quiche/src/quic/core/crypto/proof_verifier.h"
#include "net/third_party/quiche/src/quic/core/quic_connection_id.h"
#include "net/third_party/quiche/src/quic/core/quic_crypto_client_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_crypto_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/core/tls_client_handshaker.h"
#include "net/third_party/quiche/src/quic/quartc/quartc_crypto_helpers.h"
#include "owt/quic/p2p_quic_packet_transport_interface.h"
#include "owt/quic/p2p_quic_stream_interface.h"
#include "owt/quic_transport/impl/p2p_quic_stream_impl.h"
#include "owt/quic/p2p_quic_transport_interface.h"
#include "third_party/blink/renderer/modules/peerconnection/adapters/p2p_quic_crypto_config_factory_impl.h"
#include "third_party/webrtc/rtc_base/ssl_certificate.h"

namespace owt {
namespace quic {

// Length of HKDF input keying material, equal to its number of bytes.
// https://tools.ietf.org/html/rfc5869#section-2.2.
const size_t kInputKeyingMaterialLength = 32;

P2PQuicTransportImpl::P2PQuicTransportImpl(
    owt::quic::P2PQuicPacketTransportInterface* quic_packet_transport,
    const ::quic::QuicConfig& quic_config,
    ::quic::QuicCompressedCertsCache* const compressed_certs_cache,
    ::quic::QuicClock* clock,
    ::quic::QuicAlarmFactory* alarm_factory,
    ::quic::QuicConnectionHelperInterface* connection_helper,
    base::TaskRunner* runner) {
  quartc_packet_transport_ = std::make_unique<QuicPacketTransportIceAdapter>(
      quic_packet_transport, runner);
  quartc_packet_writer_ = std::make_unique<::quic::QuartcPacketWriter>(
      quartc_packet_transport_.get(), 1200);
  alarm_factory_ = alarm_factory;
  crypto_server_config_ = CreateServerCryptoConfig();
  clock_ = clock;
}

std::vector<rtc::scoped_refptr<rtc::RTCCertificate>>
P2PQuicTransportImpl::GetCertificates() const {
  return std::vector<rtc::scoped_refptr<rtc::RTCCertificate>>();
}

void P2PQuicTransportImpl::Start(
    std::unique_ptr<RTCQuicParameters> remote_parameters) {
  LOG(INFO) << "P2PQuicTransportImpl::start.";
  quartc_endpoint_ = std::make_unique<::quic::QuartcServerEndpoint>(
      alarm_factory_, clock_, ::quic::QuicRandom::GetInstance(), this,
      quartc_session_config_);
  quartc_endpoint_->Connect(quartc_packet_transport_.get());
  LOG(INFO) << "After start crypto handshake.";
}

RTCQuicParameters P2PQuicTransportImpl::GetLocalParameters() const {
  RTCQuicParameters parameters;
  parameters.role = "auto";
  return parameters;
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

// void P2PQuicTransportImpl::OnPacketDataReceived(const char* data,
//                                                 size_t data_len) {
//   LOG(INFO) << "OnPacketDataReceived.";
//   ::quic::QuicReceivedPacket packet(data, data_len, clock_->Now());
//   if (quartc_session_ && quartc_session_->connection()) {
//     LOG(INFO) << "connection is not null";
//   } else {
//     LOG(INFO) << "connection is null.";
//   }
//   quartc_session_->ProcessUdpPacket(
//       quartc_session_->connection()->self_address(),
//       quartc_session_->connection()->peer_address(), packet);
// }

std::unique_ptr<::quic::QuicCryptoServerConfig>
P2PQuicTransportImpl::CreateServerCryptoConfig() {
  // Token from
  // third_party/blink/renderer/modules/peerconnection/adapters/p2p_quic_crypto_config_factory_impl.cc
  // Generate a random source address token secret every time since this is
  // a transient client.
  char source_address_token_secret[kInputKeyingMaterialLength];
  ::quic::QuicRandom::GetInstance()->RandBytes(source_address_token_secret,
                                               kInputKeyingMaterialLength);
  std::unique_ptr<::quic::ProofSource> proof_source(
      new ::quic::DummyProofSource);
  return std::make_unique<::quic::QuicCryptoServerConfig>(
      std::string(source_address_token_secret, kInputKeyingMaterialLength),
      ::quic::QuicRandom::GetInstance(), std::move(proof_source),
      ::quic::KeyExchangeSource::Default());
}

void P2PQuicTransportImpl::Listen(const std::string& remote_key) {
  LOG(INFO) << "Pre shared key is " << remote_key.size();
  quartc_session_config_.pre_shared_key = remote_key;
  crypto_server_config_->set_pre_shared_key(remote_key);
  Start(nullptr);
}

void P2PQuicTransportImpl::Listen(uint8_t* key, size_t length){
  std::string remote_key(key, key+length);
  Listen(remote_key);
}

void P2PQuicTransportImpl::OnSessionCreated(::quic::QuartcSession* session) {
  LOG(INFO) << "OnSessionCreated.";
  session->StartCryptoHandshake();
}

void P2PQuicTransportImpl::OnIncomingStream(::quic::QuartcStream* stream) {
  LOG(INFO) << "OnIncomingStream";
  std::unique_ptr<P2PQuicStreamImpl> quic_stream =
      std::make_unique<P2PQuicStreamImpl>(stream, runner_);
  streams_.push_back(std::move(quic_stream));
  if (delegate_) {
    delegate_->OnIncomingStream(quic_stream.get());
  }
}

void P2PQuicTransportImpl::SetDelegate(
    P2PQuicTransportInterface::Delegate* delegate) {
  delegate_ = delegate;
}

}  // namespace quic
}  // namespace owt