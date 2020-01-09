/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_TRANSPORT_QUIC_TRANSPORT_FACTORY_H_
#define OWT_QUIC_TRANSPORT_QUIC_TRANSPORT_FACTORY_H_

#include <memory>
#include "export.h"
namespace quic {
class QuicAlarmFactory;
class QuicConnectionHelperInterface;
class QuicClock;
class QuicRandom;
class QuicCompressedCertsCache;
class QuicCryptoServerConfig;
}  // namespace quic

namespace base {
class Thread;
class AtExitManager;
}

namespace owt {
namespace quic {

class P2PQuicTransportInterface;
class P2PQuicPacketTransportInterface;

class OWT_EXPORT QuicTransportFactory {
 public:
  QuicTransportFactory();
  virtual ~QuicTransportFactory();
  std::unique_ptr<P2PQuicTransportInterface> CreateP2PServerTransport(
      P2PQuicPacketTransportInterface* quic_packet_transport);

 private:
  void Init();
  std::unique_ptr<::quic::QuicCryptoServerConfig> CreateServerCryptoConfig();

  std::unique_ptr<base::AtExitManager> exit_manager_;
  std::unique_ptr<base::Thread> io_thread_;
  std::unique_ptr<::quic::QuicRandom> random_generator_;
  std::unique_ptr<::quic::QuicAlarmFactory> alarm_factory_;
  std::unique_ptr<::quic::QuicConnectionHelperInterface> connection_helper_;
  std::unique_ptr<::quic::QuicCryptoServerConfig> quic_crypto_server_config_;
  std::unique_ptr<::quic::QuicCompressedCertsCache> compressed_certs_cache_;
};

}  // namespace quic
}  // namespace owt

#endif