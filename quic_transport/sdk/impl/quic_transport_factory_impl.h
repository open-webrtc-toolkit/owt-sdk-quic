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
#include "owt/quic_transport/sdk/impl/proof_verifier_owt.h"

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

namespace quic {

class OWT_EXPORT QuicTransportFactoryImpl : public QuicTransportFactory {
 public:
  QuicTransportFactoryImpl();
  ~QuicTransportFactoryImpl() override;
  void InitializeAtExitManager();
  // `accepted_origins` is removed at this time because ABI compatible issue.
  QuicTransportServerInterface* CreateQuicTransportServer(
      int port,
      const char* cert_path,
      const char* key_path) override;
  QuicTransportClientInterface* CreateQuicTransportClient(
      const char* host,
      int port) override;

 private:
  void Init();

  std::unique_ptr<base::AtExitManager> at_exit_manager_;
  std::unique_ptr<base::Thread> io_thread_;
  std::unique_ptr<base::Thread> event_thread_;
};

}  // namespace quic

#endif