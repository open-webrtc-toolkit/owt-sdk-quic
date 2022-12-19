/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "owt/quic/logging.h"
#include "owt/quic_transport/sdk/impl/quic_transport_factory_impl.h"
#include "base/at_exit.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/threading/thread.h"
#include "owt/quic_transport/sdk/impl/proof_source_owt.h"
#include "owt/quic_transport/sdk/impl/quic_transport_owt_client_impl.h"
#include "owt/quic_transport/sdk/impl/quic_transport_owt_server_impl.h"
#include "net/quic/crypto/proof_source_chromium.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/proof_source.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_types.h"
#include "url/gurl.h"
#include "net/quic/address_utils.h"
#include "net/tools/quic/synchronous_host_resolver.h"
#include "net/base/privacy_mode.h"

namespace owt {
namespace quic {

// FakeProofVerifier for client
class FakeProofVerifier : public ::quic::ProofVerifier {
 public:
  ::quic::QuicAsyncStatus VerifyProof(
      const std::string& hostname,
      const uint16_t port,
      const std::string& server_config,
      ::quic::QuicTransportVersion quic_version,
      absl::string_view  chlo_hash,
      const std::vector<std::string>& certs,
      const std::string& cert_sct,
      const std::string& signature,
      const ::quic::ProofVerifyContext* context,
      std::string* error_details,
      std::unique_ptr<::quic::ProofVerifyDetails>* details,
      std::unique_ptr<::quic::ProofVerifierCallback> callback) override {
    return ::quic::QUIC_SUCCESS;
  }

  ::quic::QuicAsyncStatus VerifyCertChain(
      const std::string& hostname,
      const uint16_t port,
      const std::vector<std::string>& certs,
      const std::string& ocsp_response,
      const std::string& cert_sct,
      const ::quic::ProofVerifyContext* verify_context,
      std::string* error_details,
      std::unique_ptr<::quic::ProofVerifyDetails>* verify_details,
      uint8_t* out_alert,
      std::unique_ptr<::quic::ProofVerifierCallback> callback) override {
    return ::quic::QUIC_SUCCESS;
  }

  std::unique_ptr<::quic::ProofVerifyContext> CreateDefaultContext() override {
    return nullptr;
  }
};

QuicTransportFactory* QuicTransportFactory::Create() {
  base::ThreadPoolInstance::CreateAndStartWithDefaultParams("quic_transport_thread_pool");
  QuicTransportFactoryImpl* factory = new QuicTransportFactoryImpl();
  factory->InitializeAtExitManager();
  return factory;
}

QuicTransportFactoryImpl::QuicTransportFactoryImpl()
    : at_exit_manager_(nullptr),
      io_thread_(std::make_unique<base::Thread>("quic_transport_io_thread")),
      event_thread_(
          std::make_unique<base::Thread>("quic_transport_event_thread")) {
  io_thread_->StartWithOptions(
      base::Thread::Options(base::MessagePumpType::IO, 0));
  event_thread_->StartWithOptions(
      base::Thread::Options(base::MessagePumpType::IO, 0));
  Init();
}

QuicTransportFactoryImpl::~QuicTransportFactoryImpl() = default;

void QuicTransportFactoryImpl::InitializeAtExitManager() {
  at_exit_manager_ = std::make_unique<base::AtExitManager>();
}

QuicTransportServerInterface* QuicTransportFactoryImpl::CreateQuicTransportServer(
    int port,
    const char* cert_file,
    const char* key_file,
    const char* secret_path) {
  auto proof_source = std::make_unique<net::ProofSourceChromium>();
  if (!proof_source->Initialize(
      base::FilePath(cert_file),
      base::FilePath(key_file), base::FilePath())) {
    LOG(ERROR) << "Failed to initialize proof source.";
    return nullptr;
  }
  return CreateQuicTransportServerOnIOThread(port, std::move(proof_source));
}

QuicTransportServerInterface* QuicTransportFactoryImpl::CreateQuicTransportServer(
    int port,
    const char* pfx_path,
    const char* password) {
  auto proof_source = std::make_unique<ProofSourceOwt>();
  if (!proof_source->Initialize(
      base::FilePath::FromUTF8Unsafe(pfx_path),
      std::string(password))) {
    LOG(ERROR) << "Failed to initialize proof source.";
    return nullptr;
  }
  return CreateQuicTransportServerOnIOThread(port, std::move(proof_source));
}

QuicTransportServerInterface* QuicTransportFactoryImpl::CreateQuicTransportServerOnIOThread(
    int port,
    std::unique_ptr<::quic::ProofSource> proof_source) {
  QuicTransportServerInterface* result(nullptr);
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  io_thread_->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](int port, std::unique_ptr<::quic::ProofSource> proof_source,
             base::Thread* io_thread, base::Thread* event_thread,
             QuicTransportServerInterface** result, base::WaitableEvent* event) {

            net::IPAddress ip = net::IPAddress::IPv6AllZeros();
            ::quic::QuicConfig config;

            *result = new net::QuicTransportOwtServerImpl(
                port, std::move(proof_source), config, 
                ::quic::QuicCryptoServerConfig::ConfigOptions(),
                ::quic::AllSupportedVersions(),
                io_thread, event_thread);
            event->Signal();
          },
          port, std::move(proof_source), base::Unretained(io_thread_.get()),
          base::Unretained(event_thread_.get()), base::Unretained(&result),
          base::Unretained(&done)));
  done.Wait();
  return result;
}

void QuicTransportFactoryImpl::Init() {
  base::CommandLine::Init(0, nullptr);
  base::CommandLine* command_line(base::CommandLine::ForCurrentProcess());
  command_line->AppendSwitch("--quic_default_to_bbr");
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_STDERR;
  logging::InitLogging(settings);
  logging::SetMinLogLevel(1);

}

QuicTransportClientInterface*
QuicTransportFactoryImpl::CreateQuicTransportClient(
    const char* host, 
    int port) {
  owt::quic::QuicTransportClientInterface* result(nullptr);
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  io_thread_->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](const char* host, int port,
             base::Thread* io_thread, base::Thread* event_thread,
             owt::quic::QuicTransportClientInterface** result, base::WaitableEvent* event) {
            std::unique_ptr<::quic::ProofVerifier> proof_verifier;
            proof_verifier.reset(new FakeProofVerifier());
            ::quic::QuicIpAddress ip_addr;

            GURL url("https://www.example.org");
            
            if (!ip_addr.FromString(host)) {
              net::AddressList addresses;
              int rv = net::SynchronousHostResolver::Resolve(url::SchemeHostPort(url::kHttpsScheme, host, port), &addresses);
              if (rv != net::OK) {
                LOG(ERROR) << "Unable to resolve '" << host
                           << "' : " << net::ErrorToShortString(rv);
                std::cerr << "Unable to resolve '" << host
                           << "' : " << net::ErrorToShortString(rv);
                return;
              }
              ip_addr =
                  net::ToQuicIpAddress(addresses[0].address());
            }

            ::quic::QuicServerId server_id(url.host(), url.EffectiveIntPort(),
                                         net::PRIVACY_MODE_DISABLED);
            ::quic::ParsedQuicVersionVector versions = ::quic::CurrentSupportedVersions();

            *result = new net::QuicTransportOwtClientImpl(
                ::quic::QuicSocketAddress(ip_addr, port), server_id, versions, std::move(proof_verifier),
                io_thread, event_thread);
            event->Signal();
          },
          base::Unretained(host), port, base::Unretained(io_thread_.get()),
          base::Unretained(event_thread_.get()), base::Unretained(&result),
          base::Unretained(&done)));
  done.Wait();
  return result;
}

}  // namespace quic
}
