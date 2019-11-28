/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_PACKET_TRANSPORT_ICE_ADAPTER_H_
#define OWT_QUIC_PACKET_TRANSPORT_ICE_ADAPTER_H_

#include "net/third_party/quiche/src/quic/quartc/quartc_packet_writer.h"

namespace base {
class TaskRunner;
}

namespace owt {
namespace quic {

class IceTransportInterface;

// P2PQuicPacketTransport uses ICE as its underlying transport channel.
class QuicPacketTransportIceAdapter : public ::quic::QuartcPacketTransport {
 public:
  QuicPacketTransportIceAdapter(std::weak_ptr<IceTransportInterface> ice_transport,
                                base::TaskRunner* runner);
  ~QuicPacketTransportIceAdapter() override;

  int Write(const char* buffer,
            size_t buffer_length,
            const PacketInfo& info) override;
  void SetDelegate(::quic::QuartcPacketTransport::Delegate* delegate) override;

 private:
  void OnReadPacket(IceTransportInterface* ice_transport,
                    const char* buffer,
                    size_t buffer_length,
                    const int64_t packet_time,
                    int flag);
  void OnReadyToSend(IceTransportInterface* ice_transport);
  void DoReadPacket(IceTransportInterface* ice_transport,
                    std::unique_ptr<char[]> buffer,
                    size_t buffer_length,
                    const int64_t packet_time,
                    int flag);
  std::weak_ptr<IceTransportInterface> ice_transport_;
  ::quic::QuartcPacketTransport::Delegate* transport_delegate_;
  base::TaskRunner* runner_;
};
}  // namespace quic
}  // namespace owt

#endif