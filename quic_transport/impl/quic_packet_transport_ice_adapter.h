/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_PACKET_TRANSPORT_ICE_ADAPTER_H_
#define OWT_QUIC_PACKET_TRANSPORT_ICE_ADAPTER_H_

#include "net/third_party/quiche/src/quic/quartc/quartc_packet_writer.h"
#include "owt/quic/p2p_quic_packet_transport_interface.h"

namespace base {
class TaskRunner;
}

namespace owt {
namespace quic {

class P2PQuicPacketTransportInterface;

// P2PQuicPacketTransportInterface uses ICE as its underlying transport channel.
class QuicPacketTransportIceAdapter : public ::quic::QuartcPacketTransport, public P2PQuicPacketTransportInterface::ReceiveDelegate, public P2PQuicPacketTransportInterface::WriteObserver {
 public:
  QuicPacketTransportIceAdapter(
      P2PQuicPacketTransportInterface* quic_packet_transport,
      base::TaskRunner* runner);
  ~QuicPacketTransportIceAdapter() override;

  int Write(const char* buffer,
            size_t buffer_length,
            const PacketInfo& info) override;
  void SetDelegate(::quic::QuartcPacketTransport::Delegate* delegate) override;

 protected:
  // P2PQuicPacketTransportInterface::ReceiveDelegate override.
  void OnPacketDataReceived(const char* data, size_t data_len) override;

  // P2PQuicPacketTransportInterface::WriteObserver override.
  void OnCanWrite() override;

 private:
  void InvokeOnTransportReceivedOnCurrentThread(char* data,
                                                size_t data_len);
  P2PQuicPacketTransportInterface* quic_packet_transport_;
  ::quic::QuartcPacketTransport::Delegate* transport_delegate_;
  base::TaskRunner* runner_;
};
}  // namespace quic
}  // namespace owt

#endif