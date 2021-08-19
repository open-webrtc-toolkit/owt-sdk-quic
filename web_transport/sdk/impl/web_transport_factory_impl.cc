/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "owt/quic/logging.h"
#include "impl/web_transport_factory_impl.h"
#include "base/at_exit.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/threading/thread.h"
#include "impl/proof_source_owt.h"
#include "impl/web_transport_owt_client_impl.h"
#include "impl/web_transport_owt_server_impl.h"
#include "net/quic/crypto/proof_source_chromium.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/third_party/quiche/src/quic/core/crypto/proof_source.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_crypto_server_config.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"

namespace owt {
namespace quic {

WebTransportFactory* WebTransportFactory::Create() {
  base::ThreadPoolInstance::CreateAndStartWithDefaultParams("web_transport_thread_pool");
  WebTransportFactoryImpl* factory = new WebTransportFactoryImpl();
  factory->InitializeAtExitManager();
  return factory;
}

WebTransportFactory* WebTransportFactory::CreateForTesting() {
  return new WebTransportFactoryImpl();
}

WebTransportFactoryImpl::WebTransportFactoryImpl()
    : at_exit_manager_(nullptr),
      io_thread_(std::make_unique<base::Thread>("quic_transport_io_thread")),
      event_thread_(
          std::make_unique<base::Thread>("quic_transport_event_thread")) {
  base::Thread::Options options;
  options.message_pump_type = base::MessagePumpType::IO;
  io_thread_->StartWithOptions(options);
  event_thread_->StartWithOptions(options);
  Init();
}

WebTransportFactoryImpl::~WebTransportFactoryImpl() = default;

void WebTransportFactoryImpl::InitializeAtExitManager() {
  at_exit_manager_ = std::make_unique<base::AtExitManager>();
}

WebTransportServerInterface*
WebTransportFactoryImpl::CreateWebTransportServer(int port,
                                                    const char* cert_path,
                                                    const char* key_path,
                                                    const char* secret_path) {
  auto proof_source = std::make_unique<net::ProofSourceChromium>();
  if (!proof_source->Initialize(base::FilePath::FromUTF8Unsafe(cert_path),
                                base::FilePath::FromUTF8Unsafe(key_path),
                                base::FilePath())) {
    LOG(ERROR) << "Failed to initialize proof source.";
    return nullptr;
  }
  return new WebTransportOwtServerImpl(port, std::vector<url::Origin>(),
                                        std::move(proof_source),
                                        io_thread_.get(), event_thread_.get());
}

WebTransportServerInterface*
WebTransportFactoryImpl::CreateWebTransportServer(int port,
                                                    const char* pfx_path,
                                                    const char* password) {
  auto proof_source = std::make_unique<ProofSourceOwt>();
  if (!proof_source->Initialize(base::FilePath::FromUTF8Unsafe(pfx_path),
                                std::string(password))) {
    LOG(ERROR) << "Failed to initialize proof source.";
    return nullptr;
  }
  return new WebTransportOwtServerImpl(port, std::vector<url::Origin>(),
                                        std::move(proof_source),
                                        io_thread_.get(), event_thread_.get());
}

WebTransportClientInterface*
WebTransportFactoryImpl::CreateWebTransportClient(const char* url) {
  WebTransportClientInterface::Parameters param;
  param.server_certificate_fingerprints_length = 0;
  return CreateWebTransportClient(url, param);
}

WebTransportClientInterface*
WebTransportFactoryImpl::CreateWebTransportClient(
    const char* url,
    const WebTransportClientInterface::Parameters& parameters) {
  WebTransportClientInterface* result(nullptr);
  net::WebTransportParameters param;
  for (size_t i = 0; i < parameters.server_certificate_fingerprints_length;
       i++) {
    owt::quic::CertificateFingerprint fingerprint =
        *parameters.server_certificate_fingerprints[i];
    ::quic::CertificateFingerprint quic_fingerprint;
    quic_fingerprint.algorithm = ::quic::CertificateFingerprint::kSha256;
    quic_fingerprint.fingerprint = fingerprint.fingerprint;
    param.server_certificate_fingerprints.push_back(quic_fingerprint);
  }
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  io_thread_->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](const char* url, const net::WebTransportParameters& param,
             base::Thread* io_thread, base::Thread* event_thread,
             WebTransportClientInterface** result,
             base::WaitableEvent* event) {
            url::Origin origin = url::Origin::Create(GURL(url));
            WebTransportClientInterface* client =
                new WebTransportOwtClientImpl(GURL(std::string(url)), origin,
                                               param, io_thread, event_thread);
            *result = client;
            event->Signal();
          },
          base::Unretained(url), param, base::Unretained(io_thread_.get()),
          base::Unretained(event_thread_.get()), base::Unretained(&result),
          base::Unretained(&done)));
  done.Wait();
  return result;
}

void WebTransportFactoryImpl::Init() {
  base::CommandLine::Init(0, nullptr);
  base::CommandLine* command_line(base::CommandLine::ForCurrentProcess());
  command_line->AppendSwitch("--quic_default_to_bbr");
  Logging::InitLogging();
}

}  // namespace quic
}  // namespace owt
