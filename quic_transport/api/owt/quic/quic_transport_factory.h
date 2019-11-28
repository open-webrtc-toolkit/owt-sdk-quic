/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_TRANSPORT_QUIC_TRANSPORT_FACTORY_H_
#define OWT_QUIC_TRANSPORT_QUIC_TRANSPORT_FACTORY_H_

#include <memory>

namespace quic {
class QuicAlarmFactory;
class QuicConnectionHelperInterface;
}  // namespace quic

namespace base {
class Thread;
}

namespace owt {
namespace quic {

class P2PQuicTransport;
class IceTransportInterface;

class QuicTransportFactory {
 public:
  QuicTransportFactory();
  static std::unique_ptr<P2PQuicTransport> CreateP2PServerTransport(
      std::weak_ptr<IceTransportInterface> ice_transport);

 private:
  std::unique_ptr<base::Thread> io_thread_;
  std::unique_ptr<quic::QuicAlarmFactory> alarm_factory_;
  std::unique_ptr<quic::QuicConnectionHelperInterface> connection_helper_;
};

}  // namespace quic
}  // namespace owt

#endif