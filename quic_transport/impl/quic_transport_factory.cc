/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "owt/quic/quic_transport_factory.h"
#include "base/at_exit.h"
#include "base/logging.h"
#include "base/threading/thread.h"
#include "impl/p2p_quic_transport_impl.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/third_party/quiche/src/quic/core/crypto/proof_source.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_crypto_server_config.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/quartc/quartc_crypto_helpers.h"
#include "net/third_party/quiche/src/quic/quartc/quartc_factory.h"

namespace owt {
namespace quic {

// Length of HKDF input keying material, equal to its number of bytes.
// https://tools.ietf.org/html/rfc5869#section-2.2.
const size_t kInputKeyingMaterialLength = 32;

QuicTransportFactory::QuicTransportFactory()
    : exit_manager_(std::make_unique<base::AtExitManager>()),
      io_thread_(std::make_unique<base::Thread>("quic_transport_io_thread")),
      random_generator_(::quic::QuicRandom::GetInstance()),
      alarm_factory_(std::make_unique<net::QuicChromiumAlarmFactory>(
          io_thread_->task_runner().get(),
          ::quic::QuicChromiumClock::GetInstance())),
      connection_helper_(std::make_unique<net::QuicChromiumConnectionHelper>(
          ::quic::QuicChromiumClock::GetInstance(),
          random_generator_.get())),
      quic_crypto_server_config_(CreateServerCryptoConfig()),
      compressed_certs_cache_(std::make_unique<
                              ::quic::QuicCompressedCertsCache>(
          ::quic::QuicCompressedCertsCache::kQuicCompressedCertsCacheSize)) {
  // TODO: Move logging settings to somewhere else.
  Init();
  LOG(INFO) << "Ctor of QuicTransportFactory.";
}

QuicTransportFactory::~QuicTransportFactory() = default;

std::unique_ptr<P2PQuicTransportInterface>
QuicTransportFactory::CreateP2PServerTransport(
    P2PQuicPacketTransportInterface* quic_packet_transport) {
  return std::make_unique<P2PQuicTransportImpl>(
      quic_packet_transport, ::quic::QuicConfig(),
      quic_crypto_server_config_.get(), compressed_certs_cache_.get(),
      ::quic::QuicChromiumClock::GetInstance(), alarm_factory_.get(),
      connection_helper_.get(), io_thread_->task_runner().get());
}
void QuicTransportFactory::Init() {
  base::CommandLine::Init(0, nullptr);
  // Logging settings for Chromium.
  logging::SetMinLogLevel(logging::LOG_VERBOSE);
  logging::LoggingSettings settings;
  //settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  InitLogging(settings);
}

std::unique_ptr<::quic::QuicCryptoServerConfig>
QuicTransportFactory::CreateServerCryptoConfig() {
  // Token from
  // third_party/blink/renderer/modules/peerconnection/adapters/p2p_quic_crypto_config_factory_impl.cc
  // Generate a random source address token secret every time since this is
  // a transient client.
  char source_address_token_secret[kInputKeyingMaterialLength];
  random_generator_->RandBytes(source_address_token_secret,
                               kInputKeyingMaterialLength);
  std::unique_ptr<::quic::ProofSource> proof_source(
      new ::quic::DummyProofSource);
  return std::make_unique<::quic::QuicCryptoServerConfig>(
      std::string(source_address_token_secret, kInputKeyingMaterialLength),
      random_generator_.get(), std::move(proof_source),
      ::quic::KeyExchangeSource::Default());
}
}  // namespace quic
}  // namespace owt
