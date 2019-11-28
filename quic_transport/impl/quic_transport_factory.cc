/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "owt/quic/quic_transport_factory.h"
#include "base/threading/thread.h"
#include "impl/p2p_quic_transport_impl.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/quartc/quartc_factory.h"
#include "owt/quic/p2p_quic_transport.h"

namespace owt {
namespace quic {
QuicTransportFactory::QuicTransportFactory()
    : io_thread_(std::make_unique<base::Thread>("quic_transport_io_thread")),
      alarm_factory_(std::make_unique<net::QuicChromiumAlarmFactory>(
          io_thread_->task_runner().get(),
          ::quic::QuicChromiumClock::GetInstance())),
      connection_helper_(std::unique_ptr<quic::QuicConnectionHelperInterface>(
          ::quic::QuicChromiumClock::GetInstance())) {}

std::unique_ptr<P2PQuicTransport>
QuicTransportFactory::CreateP2PServerTransport(
    std::weak_ptr<IceTransportInterface> ice_transport) {
  P2PQuicTransportImpl::Create(::quic::QuartcSessionConfig(),
                               ::quic::Perspective::IS_SERVER, nullptr /*TODO*/,
                               ::quic::QuicChromiumClock(),
                               alarm_factory_.get(), nullptr /*cryptoConfig*/, )
}
}  // namespace quic
}  // namespace owt
