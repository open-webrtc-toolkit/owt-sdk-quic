/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Most classes in this file and its implementations are borrowed from
// Chromium/src/third_party/blink/renderer/modules/peerconnection/adapters/*
// with modifications.

#ifndef OWT_QUIC_TRANSPORT_P2P_QUIC_TRANSPORT_IMPL_H_
#define OWT_QUIC_TRANSPORT_P2P_QUIC_TRANSPORT_IMPL_H_

#include "base/at_exit.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_compressed_certs_cache.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_crypto_client_config.h"
#include "net/third_party/quiche/src/quic/quartc/quartc_endpoint.h"
#include "net/third_party/quiche/src/quic/quartc/quartc_factory.h"
#include "net/third_party/quiche/src/quic/quartc/quartc_session.h"
#include "owt/quic/p2p_quic_packet_transport_interface.h"
#include "owt/quic/p2p_quic_transport_interface.h"
#include "owt/quic/quic_definitions.h"
#include "third_party/webrtc/api/scoped_refptr.h"
#include "third_party/webrtc/rtc_base/rtc_certificate.h"

namespace owt {
namespace quic {
// Some ideas of this class are borrowed from
// src/third_party/blink/renderer/modules/peerconnection/adapters/p2p_quic_transport_impl.h.
// It always acts as a server side endpoint.
class P2PQuicTransportImpl : public P2PQuicTransportInterface,
                             public ::quic::QuartcEndpoint::Delegate {
 public:
  static std::unique_ptr<P2PQuicTransportImpl> Create(
      const ::quic::QuartcSessionConfig& quartcSessionConfig,
      ::quic::Perspective perspective,
      std::shared_ptr<::quic::QuartcPacketTransport> transport,
      ::quic::QuicClock* clock,
      std::shared_ptr<::quic::QuicAlarmFactory> alarmFactory,
      std::shared_ptr<::quic::QuicConnectionHelperInterface> helper,
      std::shared_ptr<::quic::QuicCryptoServerConfig> cryptoServerConfig,
      ::quic::QuicCompressedCertsCache* const compressedCertsCache,
      base::TaskRunner* runner);
  virtual std::vector<rtc::scoped_refptr<rtc::RTCCertificate>> GetCertificates()
      const;
  virtual void Start(std::unique_ptr<RTCQuicParameters> remote_parameters);
  RTCQuicParameters GetLocalParameters() const override;
  void Listen(const std::string& remote_key) override;
  void Listen(uint8_t* key, size_t length) override;

  void SetDelegate(P2PQuicTransportInterface::Delegate* delegate) override;

  explicit P2PQuicTransportImpl(
      owt::quic::P2PQuicPacketTransportInterface* quic_packet_transport,
      const ::quic::QuicConfig& quic_config,
      ::quic::QuicCompressedCertsCache* const compressed_certs_cache,
      ::quic::QuicClock* clock,
      ::quic::QuicAlarmFactory* alarm_factory,
      ::quic::QuicConnectionHelperInterface* connection_helper,
      base::TaskRunner* runner);
  ~P2PQuicTransportImpl() override;

 protected:
  // QuartcSession::Delegate overrides.
  void OnCryptoHandshakeComplete() override {}
  void OnConnectionWritable() override {}
  void OnIncomingStream(::quic::QuartcStream* stream) override;
  void OnCongestionControlChange(::quic::QuicBandwidth bandwidth_estimate,
                                 ::quic::QuicBandwidth pacing_rate,
                                 ::quic::QuicTime::Delta latest_rtt) override {}
  void OnConnectionClosed(const ::quic::QuicConnectionCloseFrame& frame,
                          ::quic::ConnectionCloseSource source) override {}
  void OnMessageReceived(::quic::QuicStringPiece message) override {}
  void OnMessageSent(int64_t datagram_id) override {}
  void OnMessageAcked(int64_t datagram_id,
                      ::quic::QuicTime receive_timestamp) override {}
  void OnMessageLost(int64_t datagram_id) override {}
  void OnSessionCreated(::quic::QuartcSession* session) override;

 private:
  std::unique_ptr<::quic::QuicCryptoServerConfig> CreateServerCryptoConfig();
  void CreateAndConnectQuartcEndpointOnCurrentThread();

  std::shared_ptr<::quic::QuartcPacketWriter> packet_writer_;
  std::unique_ptr<::quic::QuicCryptoServerConfig> crypto_server_config_;
  ::quic::QuartcSessionConfig quartc_session_config_;
  ::quic::QuicAlarmFactory* alarm_factory_;
  P2PQuicTransportInterface::Delegate* delegate_;
  std::vector<std::unique_ptr<P2PQuicStreamInterface>> streams_;
  base::TaskRunner* runner_;
  std::unique_ptr<::quic::QuartcPacketTransport> quartc_packet_transport_;
  std::unique_ptr<::quic::QuartcPacketWriter> quartc_packet_writer_;
  std::unique_ptr<::quic::QuartcServerEndpoint> quartc_endpoint_;
  ::quic::QuicClock* clock_;
};
}  // namespace quic
}  // namespace owt

#endif