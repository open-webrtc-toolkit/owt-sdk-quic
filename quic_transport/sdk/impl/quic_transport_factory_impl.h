/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_TRANSPORT_FACTORY_IMPL_H_
#define OWT_QUIC_TRANSPORT_FACTORY_IMPL_H_

#include <memory>
#include <string>
#include <vector>
#include "owt/quic/export.h"
#include "owt/quic/quic_transport_factory.h"
#include "owt/quic_transport/sdk/impl/proof_source_owt.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_default_proof_providers.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_types.h"
#include "quiche/quic/core/crypto/web_transport_fingerprint_proof_verifier.h"

namespace quic {
class QuicAlarmFactory;
class QuicConnectionHelperInterface;
class QuicClock;
//class QuicRandom;
class QuicCompressedCertsCache;
class QuicCryptoServerConfig;
class ProofSource;
}  // namespace quic

namespace base {
class Thread;
class AtExitManager;
}  // namespace base

namespace owt {
namespace quic {

class OWT_EXPORT QuicTransportFactoryImpl : public owt::quic::QuicTransportFactory {
 public:
  QuicTransportFactoryImpl();
  ~QuicTransportFactoryImpl() override;
  void InitializeAtExitManager();
  // `accepted_origins` is removed at this time because ABI compatible issue.
  QuicTransportServerInterface* CreateQuicTransportServer(
      int port,
      const char* cert_path,
      const char* key_path,
      const char* secret_path) override;
  QuicTransportServerInterface* CreateQuicTransportServer(
    int port,
    const char* pfx_path,
    const char* password) override;
  QuicTransportClientInterface* CreateQuicTransportClient(
      const char* host,
      int port) override;

 private:
  void Init();
  QuicTransportServerInterface* CreateQuicTransportServerOnIOThread(
      int port,
      std::unique_ptr<::quic::ProofSource> proof_source);

  std::unique_ptr<base::AtExitManager> at_exit_manager_;
  std::unique_ptr<base::Thread> io_thread_;
  std::unique_ptr<base::Thread> event_thread_;
  std::vector<::quic::CertificateFingerprint> server_certificate_fingerprints;
};

}  // namespace quic
}

#endif
