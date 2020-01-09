/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_P2P_QUIC_PACKET_TRANSPORT_INTERFACE_H_
#define OWT_QUIC_P2P_QUIC_PACKET_TRANSPORT_INTERFACE_H_

/* Borrowered from
 * //third_party/blink/renderer/modules/peerconnection/adapters/p2p_quic_packet_transport.h
 */

#include <cstddef>
#include "export.h"

namespace owt {
namespace quic {
// This is the interface for the underlying packet transport used by the
// P2PQuicTransport for receiving and writing data. The standard
// implementation of this interface uses an ICE transport.
class OWT_EXPORT P2PQuicPacketTransportInterface {
 public:
  // This is subclassed by the P2PQuicTransport so that it can receive incoming
  // data. The standard case is for this to be the P2PQuicTransport.
  // The P2PQuicPacketTransportInterface will outlive the ReceiveDelegate.
  class ReceiveDelegate {
   public:
    virtual ~ReceiveDelegate() = default;
    virtual void OnPacketDataReceived(const char* data, size_t data_len) = 0;
  };

  // This is subclassed by the Writer, so that it is aware when the
  // P2PQuicPacketTransportInterface is ready to write data. The
  // P2PQuicPacketTransportInterface will outlive the WriteObserver.
  class WriteObserver {
   public:
    virtual ~WriteObserver() = default;
    virtual void OnCanWrite() = 0;
  };

  virtual ~P2PQuicPacketTransportInterface() = default;

  // Write QUIC packets to the network. Return the number of written bytes.
  // Return 0 if the write is blocked.
  virtual int WritePacket(const char* buffer, size_t buf_len) = 0;
  // Sets the ReceiveDelegate for receiving packets.
  // Since the ReceiveDelegate has a shorter lifetime than the
  // P2PQuicPacketTransportInterface, it must unset itself upon destruction.
  virtual void SetReceiveDelegate(ReceiveDelegate* receive_delegate) = 0;
  // Sets the WriteObserver for obsererving when it can write to the
  // P2PQuicPacketTransportInterface. Since the WriteObserver has a shorter
  // lifetime than the P2PQuicPacketTransportInterface, it must unset itself
  // upon destruction.
  virtual void SetWriteObserver(WriteObserver* write_observer) = 0;
  // Returns true if the P2PQuicPacketTransportInterface can write.
  virtual bool Writable() = 0;
};
}  // namespace quic
}  // namespace owt

#endif