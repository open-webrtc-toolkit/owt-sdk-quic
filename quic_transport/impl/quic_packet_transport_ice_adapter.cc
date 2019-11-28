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
#include "owt/quic/ice_transport_interface.h"
#include "third_party/webrtc/rtc_base/time_utils.h"

namespace owt {
namespace quic {

QuicPacketTransportIceAdapter::QuicPacketTransportIceAdapter(
    std::weak_ptr<IceTransportInterface> ice_transport,
    base::TaskRunner* runner) {
  ice_transport_ = ice_transport;
  runner_ = runner;
}

QuicPacketTransportIceAdapter::~QuicPacketTransportIceAdapter() {
  LOG(INFO) << "QuicPacketTransportIceAdapter::~QuicPacketTransportIceAdapter";
}

int QuicPacketTransportIceAdapter::Write(
    const char* buffer,
    size_t buffer_length,
    const ::quic::QuartcPacketTransport::PacketInfo& info) {
  LOG(INFO) << "QuicPacketTransportIceAdapter::write";
  if (auto ptr = ice_transport_.lock()) {
    return ptr->SendPacket(buffer, buffer_length);
  }
  return 0;
}

void QuicPacketTransportIceAdapter::SetDelegate(
    ::quic::QuartcPacketTransport::Delegate* delegate) {
  LOG(INFO) << "QuicPacketTransportIceAdapter::SetDelegate";
  transport_delegate_ = delegate;
}

void QuicPacketTransportIceAdapter::DoReadPacket(
    IceTransportInterface* ice_transport,
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
    IceTransportInterface* ice_transport,
    const char* buffer,
    size_t buffer_length,
    const int64_t packetTime,
    int flag) {
  LOG(INFO) << "QuicPacketTransportIceAdapter::onReadPacket";
  std::unique_ptr<char[]> buffer_copied =
      std::make_unique<char[]>(buffer_length);
  memcpy(buffer_copied.get(), buffer, buffer_length);
  runner_->PostTask(FROM_HERE,
                    base::BindOnce(&QuicPacketTransportIceAdapter::DoReadPacket,
                                   base::Unretained(this), ice_transport,
                                   std::move(buffer_copied), buffer_length,
                                   packetTime, flag));
}

void QuicPacketTransportIceAdapter::OnReadyToSend(
    IceTransportInterface* ice_transport) {
  LOG(INFO) << "QuicPacketTransportIceAdapter::onReadyToSend";
  if (!transport_delegate_) {
    return;
  }
  transport_delegate_->OnTransportCanWrite();
}
}  // namespace quic
}  // namespace owt