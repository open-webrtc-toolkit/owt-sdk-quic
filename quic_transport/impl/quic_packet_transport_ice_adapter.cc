/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "owt/quic_transport/impl/quic_packet_transport_ice_adapter.h"
#include "base/bind.h"
#include "base/logging.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_runner.h"
#include "impl/quic_packet_transport_ice_adapter.h"
#include "owt/quic/p2p_quic_transport_interface.h"
#include "third_party/webrtc/rtc_base/time_utils.h"

namespace owt {
namespace quic {

QuicPacketTransportIceAdapter::QuicPacketTransportIceAdapter(
    P2PQuicPacketTransportInterface* quic_packet_transport,
    base::TaskRunner* runner) {
  LOG(INFO) << "QuicPacketTransportIceAdapter::QuicPacketTransportIceAdapter";
  CHECK(runner);
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
  char data_copy[data_len];
  memcpy(data_copy, data, data_len);
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  runner_->PostTask(
      FROM_HERE, base::BindOnce(&QuicPacketTransportIceAdapter::
                                    InvokeOnTransportReceivedOnCurrentThread,
                                base::Unretained(this),
                                base::Unretained(data_copy), data_len, &done));
  done.Wait();
}

void QuicPacketTransportIceAdapter::InvokeOnTransportReceivedOnCurrentThread(
    char* data,
    size_t data_len,
    base::WaitableEvent* done) {
  if (transport_delegate_) {
    transport_delegate_->OnTransportReceived(data, data_len);
  }
  done->Signal();
}

void QuicPacketTransportIceAdapter::OnCanWrite() {
  if (transport_delegate_) {
    LOG(INFO) << "OnTransportCanWrite.";
    runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            &::quic::QuartcPacketTransport::Delegate::OnTransportCanWrite,
            base::Unretained(transport_delegate_)));
  }
}

}  // namespace quic
}  // namespace owt