/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "owt/quic_transport/impl/quic_packet_transport_ice_adapter.h"
#include "base/bind.h"
#include "base/logging.h"
#include "base/task_runner.h"
#include "impl/quic_packet_transport_ice_adapter.h"
#include "owt/quic/p2p_quic_transport_interface.h"
#include "third_party/webrtc/rtc_base/time_utils.h"

namespace owt {
namespace quic {

QuicPacketTransportIceAdapter::QuicPacketTransportIceAdapter(
    P2PQuicPacketTransportInterface* quic_packet_transport,
    base::TaskRunner* runner) {
  LOG(INFO) <<"QuicPacketTransportIceAdapter::QuicPacketTransportIceAdapter";
  quic_packet_transport_ = quic_packet_transport;
  runner_ = runner;
  quic_packet_transport->SetReceiveDelegate(this);
  quic_packet_transport->SetWriteObserver(this);
}

QuicPacketTransportIceAdapter::~QuicPacketTransportIceAdapter() {
  LOG(INFO) << "QuicPacketTransportIceAdapter::~QuicPacketTransportIceAdapter";
}

int QuicPacketTransportIceAdapter::Write(
    const char* buffer,
    size_t buffer_length,
    const ::quic::QuartcPacketTransport::PacketInfo& info) {
  LOG(INFO) << "QuicPacketTransportIceAdapter::write";
  return quic_packet_transport_->WritePacket(buffer, buffer_length);
}

void QuicPacketTransportIceAdapter::SetDelegate(
    ::quic::QuartcPacketTransport::Delegate* delegate) {
  LOG(INFO) << "QuicPacketTransportIceAdapter::SetDelegate";
  transport_delegate_ = delegate;
}

void QuicPacketTransportIceAdapter::OnPacketDataReceived(const char* data,
                                                         size_t data_len) {
  if (transport_delegate_) {
    transport_delegate_->OnTransportReceived(data, data_len);
  }
}

void QuicPacketTransportIceAdapter::OnCanWrite() {
  if (transport_delegate_) {
    LOG(INFO)<<"OnTransportCanWrite.";
    transport_delegate_->OnTransportCanWrite();
  }
}

void QuicPacketTransportIceAdapter::DoReadPacket(
    P2PQuicPacketTransportInterface* quic_packet_transport,
    std::unique_ptr<char[]> buffer,
    size_t buffer_length,
    const int64_t packetTime,
    int flag) {
  if (!transport_delegate_) {
    return;
  }
  transport_delegate_->OnTransportReceived(buffer.get(), buffer_length);
}

void QuicPacketTransportIceAdapter::OnReadPacket(
    P2PQuicPacketTransportInterface* quic_packet_transport,
    const char* buffer,
    size_t buffer_length,
    const int64_t packetTime,
    int flag) {
  LOG(INFO) << "QuicPacketTransportIceAdapter::onReadPacket";
  std::unique_ptr<char[]> buffer_copied =
      std::make_unique<char[]>(buffer_length);
  memcpy(buffer_copied.get(), buffer, buffer_length);
  runner_->PostTask(
      FROM_HERE, base::BindOnce(&QuicPacketTransportIceAdapter::DoReadPacket,
                                base::Unretained(this), quic_packet_transport,
                                std::move(buffer_copied), buffer_length,
                                packetTime, flag));
}

void QuicPacketTransportIceAdapter::OnReadyToSend(
    P2PQuicPacketTransportInterface* quic_packet_transport) {
  LOG(INFO) << "QuicPacketTransportIceAdapter::onReadyToSend";
  if (!transport_delegate_) {
    return;
  }
  transport_delegate_->OnTransportCanWrite();
}
}  // namespace quic
}  // namespace owt