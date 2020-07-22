/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "impl/quic_transport_factory_impl.h"
#include "base/at_exit.h"
#include "base/logging.h"
#include "base/threading/thread.h"
#include "impl/quic_transport_owt_client_impl.h"
#include "impl/quic_transport_owt_server_impl.h"
#include "net/quic/crypto/proof_source_chromium.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/third_party/quiche/src/quic/core/crypto/proof_source.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_crypto_server_config.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"

namespace owt {
namespace quic {

QuicTransportFactory* QuicTransportFactory::Create() {
  return new QuicTransportFactoryImpl();
}

std::unique_ptr<::quic::ProofSource> CreateProofSource() {
  auto proof_source = std::make_unique<net::ProofSourceChromium>();
  proof_source->Initialize(
      base::FilePath("/home/jianjunz/Documents/certs/"
                     "jianjunz-nuc-ubuntu.sh.intel.com.untrust.crt"),
      base::FilePath("/home/jianjunz/Documents/certs/"
                     "jianjunz-nuc-ubuntu.sh.intel.com.untrust.pkcs8"),
      base::FilePath());
  return proof_source;
}

QuicTransportFactoryImpl::QuicTransportFactoryImpl()
    : exit_manager_(std::make_unique<base::AtExitManager>()),
      io_thread_(std::make_unique<base::Thread>("quic_transport_io_thread")),
      connection_helper_(std::make_unique<net::QuicChromiumConnectionHelper>(
          ::quic::QuicChromiumClock::GetInstance(),
          ::quic::QuicRandom::GetInstance())),
      compressed_certs_cache_(std::make_unique<
                              ::quic::QuicCompressedCertsCache>(
          ::quic::QuicCompressedCertsCache::kQuicCompressedCertsCacheSize)) {
  base::Thread::Options options;
  options.message_pump_type = base::MessagePumpType::IO;
  io_thread_->StartWithOptions(options);
  alarm_factory_ = std::make_unique<net::QuicChromiumAlarmFactory>(
      io_thread_->task_runner().get(),
      ::quic::QuicChromiumClock::GetInstance());
  // TODO: Move logging settings to somewhere else.
  Init();
  LOG(INFO) << "Ctor of QuicTransportFactory.";
}

QuicTransportFactoryImpl::~QuicTransportFactoryImpl() = default;

QuicTransportServerInterface*
QuicTransportFactoryImpl::CreateQuicTransportServer(int port,
                                                    const char* cert_path,
                                                    const char* key_path,
                                                    const char* secret_path) {
  LOG(INFO) << "QuicTransportFactoryImpl::CreateQuicTransportServer";
  return new QuicTransportOwtServerImpl(port, std::vector<url::Origin>(),
                                        CreateProofSource(), io_thread_.get());
}

void QuicTransportFactoryImpl::ReleaseQuicTransportServer(
    const QuicTransportServerInterface* server) {
  delete reinterpret_cast<const QuicTransportOwtServerImpl*>(server);
}

QuicTransportClientInterface*
QuicTransportFactoryImpl::CreateQuicTransportClient(const char* url) {
  return new QuicTransportOwtClientImpl(GURL(std::string(url)));
}

QuicTransportClientInterface*
QuicTransportFactoryImpl::CreateQuicTransportClient(
    const char* url,
    const QuicTransportClientInterface::Parameters& parameters) {
  net::QuicTransportClient::Parameters param;
  for (size_t i = 0; i < parameters.server_certificate_fingerprints_length;
       i++) {
    owt::quic::CertificateFingerprint fingerprint =
        *parameters.server_certificate_fingerprints[i];
    ::quic::CertificateFingerprint quic_fingerprint;
    quic_fingerprint.algorithm = ::quic::CertificateFingerprint::kSha256;
    quic_fingerprint.fingerprint = fingerprint.fingerprint;
    param.server_certificate_fingerprints.push_back(quic_fingerprint);
  }
  return new QuicTransportOwtClientImpl(GURL(std::string(url)), param);
}

void QuicTransportFactoryImpl::Init() {
  base::CommandLine::Init(0, nullptr);
  base::CommandLine* command_line(base::CommandLine::ForCurrentProcess());
  command_line->AppendSwitch("--quic_default_to_bbr");
  // Logging settings for Chromium.
#ifdef _DEBUG
  logging::SetMinLogLevel(logging::LOG_INFO);
#else
  logging::SetMinLogLevel(logging::LOG_INFO);
#endif
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_STDERR;
  InitLogging(settings);
}

}  // namespace quic
}  // namespace owt
