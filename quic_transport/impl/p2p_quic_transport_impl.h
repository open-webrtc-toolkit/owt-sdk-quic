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
#include "net/third_party/quiche/src/quic/quartc/quartc_factory.h"
#include "net/third_party/quiche/src/quic/quartc/quartc_session.h"
#include "owt/quic/quic_definitions.h"
#include "owt/quic/p2p_quic_transport.h"
#include "third_party/webrtc/api/scoped_refptr.h"
#include "third_party/webrtc/rtc_base/rtc_certificate.h"

namespace owt {
namespace quic {
// Some ideas of this class are borrowed from
// src/third_party/blink/renderer/modules/peerconnection/adapters/p2p_quic_transport_impl.h.
class P2PQuicTransportImpl : public ::quic::QuartcServerSession,
                             public P2PQuicTransport {
 public:
  static std::unique_ptr<P2PQuicTransportImpl> create(
      const ::quic::QuartcSessionConfig& quartcSessionConfig,
      ::quic::Perspective perspective,
      std::shared_ptr<::quic::QuartcPacketTransport> transport,
      ::quic::QuicClock* clock,
      std::shared_ptr<::quic::QuicAlarmFactory> alarmFactory,
      std::shared_ptr<::quic::QuicConnectionHelperInterface> helper,
      std::shared_ptr<::quic::QuicCryptoServerConfig> cryptoServerConfig,
      ::quic::QuicCompressedCertsCache* const compressedCertsCache,
      base::TaskRunner* runner);
  virtual std::vector<rtc::scoped_refptr<rtc::RTCCertificate>> getCertificates()
      const;
  virtual void start(std::unique_ptr<RTCQuicParameters> remoteParameters);
  // virtual void listen(const std::string& remoteKey);
  virtual RTCQuicParameters getLocalParameters() const;

  void SetDelegate(P2PQuicTransport::Delegate* delegate) {
    m_delegate = delegate;
  }

  explicit P2PQuicTransportImpl(
      std::unique_ptr<::quic::QuicConnection> connection,
      const ::quic::QuicConfig& config,
      ::quic::QuicClock* clock,
      std::shared_ptr<::quic::QuartcPacketWriter> packetWriter,
      std::shared_ptr<::quic::QuicCryptoServerConfig> cryptoServerConfig,
      ::quic::QuicCompressedCertsCache* const compressedCertsCache,
      base::TaskRunner* runner);
  ~P2PQuicTransportImpl() override;

 protected:
  void OnConnectionClosed(const ::quic::QuicConnectionCloseFrame& frame,
                          ::quic::ConnectionCloseSource source) override;
  void OnMessageReceived(::quic::QuicStringPiece message) override;
  // void OnMessageSent(quic::QuicStringPiece message) override;
  void OnMessageAcked(::quic::QuicMessageId message_id,
                      ::quic::QuicTime receive_timestamp) override;
  void OnMessageLost(::quic::QuicMessageId message_id) override;

 private:
  static std::unique_ptr<::quic::QuicConnection> createQuicConnection(
      ::quic::Perspective perspective,
      std::shared_ptr<::quic::QuartcPacketWriter> writer,
      std::shared_ptr<::quic::QuicAlarmFactory> alarmFactory,
      std::shared_ptr<::quic::QuicConnectionHelperInterface> connectionHelper);
  std::shared_ptr<::quic::QuartcPacketWriter> m_writer;
  std::shared_ptr<::quic::QuicCryptoServerConfig> m_cryptoServerConfig;
  P2PQuicTransport::Delegate* m_delegate;
  std::vector<std::unique_ptr<P2PQuicStream>> m_streams;
  base::TaskRunner* m_runner;
};
}  // namespace quic
}  // namespace owt

#endif