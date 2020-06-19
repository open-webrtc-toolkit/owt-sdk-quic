/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_TRANSPORT_QUIC_TRANSPORT_FACTORY_IMPL_H_
#define OWT_QUIC_TRANSPORT_QUIC_TRANSPORT_FACTORY_IMPL_H_

#include <memory>
#include <string>
#include <vector>
#include "owt/quic/export.h"
#include "owt/quic/quic_transport_factory.h"

namespace quic {
class QuicAlarmFactory;
class QuicConnectionHelperInterface;
class QuicClock;
class QuicRandom;
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

class OWT_EXPORT QuicTransportFactoryImpl : public QuicTransportFactory {
 public:
  QuicTransportFactoryImpl();
  ~QuicTransportFactoryImpl() override;
  // `accepted_origins` is removed at this time because ABI compatible issue.
  QuicTransportServerInterface* CreateQuicTransportServer(
      int port,
      const char* cert_path,
      const char* key_path,
      const char* secret_path /*, std::vector<std::string> accepted_origins*/)
      override;
  void ReleaseQuicTransportServer(
      const QuicTransportServerInterface* server) override;

 private:
  void Init();

  std::unique_ptr<base::AtExitManager> exit_manager_;
  std::unique_ptr<base::Thread> io_thread_;
  std::unique_ptr<::quic::QuicRandom> random_generator_;
  std::unique_ptr<::quic::QuicAlarmFactory> alarm_factory_;
  std::unique_ptr<::quic::QuicConnectionHelperInterface> connection_helper_;
  std::unique_ptr<::quic::QuicCompressedCertsCache> compressed_certs_cache_;
};

}  // namespace quic
}  // namespace owt

#endif