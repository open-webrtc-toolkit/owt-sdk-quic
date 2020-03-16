/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Most classes in this file and its implementations are borrowed from
// Chromium/net/tools/quic/quic_transport_simple_server.cc
// with modifications.

#include "impl/quic_transport_server_impl.h"
#include "base/bind.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/net_errors.h"
#include "net/quic/address_utils.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/third_party/quiche/src/quic/core/quic_crypto_server_stream_base.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_default_proof_providers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_system_event_loop.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_protocol.h"
#include "net/third_party/quiche/src/quic/tools/quic_transport_simple_server_dispatcher.h"
#include "net/tools/quic/quic_simple_server_packet_writer.h"
#include "net/tools/quic/quic_simple_server_socket.h"

namespace owt {
namespace quic {

constexpr char kSourceAddressTokenSecret[] = "owt";
constexpr size_t kMaxReadsPerEvent = 32;
constexpr size_t kMaxNewConnectionsPerEvent = 32;
constexpr int kReadBufferSize = 2 * ::quic::kMaxIncomingPacketSize;

class QuicTransportServerImplSessionHelper
    : public ::quic::QuicCryptoServerStreamBase::Helper {
 public:
  bool CanAcceptClientHello(const ::quic::CryptoHandshakeMessage& /*message*/,
                            const ::quic::QuicSocketAddress& /*client_address*/,
                            const ::quic::QuicSocketAddress& /*peer_address*/,
                            const ::quic::QuicSocketAddress& /*self_address*/,
                            std::string* /*error_details*/) const override {
    return true;
  }
};

QuicTransportServerImpl::QuicTransportServerImpl(
    int port,
    std::vector<url::Origin> accepted_origins,
    std::unique_ptr<::quic::ProofSource> proof_source,
    base::Thread* io_thread)
    : port_(port),
      version_manager_({::quic::DefaultVersionForQuicTransport()}),
      clock_(::quic::QuicChromiumClock::GetInstance()),
      crypto_config_(kSourceAddressTokenSecret,
                     ::quic::QuicRandom::GetInstance(),
                     std::move(proof_source),
                     ::quic::KeyExchangeSource::Default()),
      dispatcher_(nullptr),
      task_runner_(io_thread->task_runner()),
      read_buffer_(
          base::MakeRefCounted<net::IOBufferWithSize>(kReadBufferSize)) {
  dispatcher_ = std::make_unique<::quic::QuicTransportSimpleServerDispatcher>(
      &config_, &crypto_config_, &version_manager_,
      std::make_unique<net::QuicChromiumConnectionHelper>(
          clock_, ::quic::QuicRandom::GetInstance()),
      std::make_unique<QuicTransportServerImplSessionHelper>(),
      std::make_unique<net::QuicChromiumAlarmFactory>(task_runner_.get(),
                                                      clock_),
      ::quic::kQuicDefaultConnectionIdLength, accepted_origins);
}

QuicTransportServerImpl::~QuicTransportServerImpl() {}

int QuicTransportServerImpl::Start() {
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&QuicTransportServerImpl::StartOnCurrentThread,
                                base::Unretained(this), &done));
  done.Wait();
  if (socket_) {
    LOG(INFO) << "QUIC transport server is listening " << server_address_.ToString();
    return EXIT_SUCCESS;
  } else {
    LOG(ERROR) << "Failed to start QUIC transport server.";
    return EXIT_FAILURE;
  }
}

void QuicTransportServerImpl::StartOnCurrentThread(base::WaitableEvent* done) {
  LOG(INFO) << "QuicTransportServerImpl::StartOnCurrentThread";
  socket_ = net::CreateQuicSimpleServerSocket(
      net::IPEndPoint{net::IPAddress::IPv6AllZeros(), port_}, &server_address_);
  if (socket_ == nullptr) {
    done->Signal();
    return;
  }

  dispatcher_->InitializeWithWriter(
      new net::QuicSimpleServerPacketWriter(socket_.get(), dispatcher_.get()));
  ScheduleReadPackets();
  done->Signal();
  LOG(INFO) << "End of QuicTransportServerImpl::StartOnCurrentThread";
  return;
}

void QuicTransportServerImpl::Stop() {}

void QuicTransportServerImpl::SetVisitor(
    QuicTransportServerInterface::Visitor* visitor) {}

void QuicTransportServerImpl::ScheduleReadPackets() {
  task_runner_->PostTask(FROM_HERE,
                         base::BindOnce(&QuicTransportServerImpl::ReadPackets,
                                        weak_factory_.GetWeakPtr()));
}

void QuicTransportServerImpl::ReadPackets() {
  dispatcher_->ProcessBufferedChlos(kMaxNewConnectionsPerEvent);
  for (size_t i = 0; i < kMaxReadsPerEvent; i++) {
    int result = socket_->RecvFrom(
        read_buffer_.get(), read_buffer_->size(), &client_address_,
        base::BindOnce(&QuicTransportServerImpl::OnReadComplete,
                       base::Unretained(this)));
    if (result == net::ERR_IO_PENDING){
      return;
    }
    ProcessReadPacket(result);
  }
  ScheduleReadPackets();
}

void QuicTransportServerImpl::OnReadComplete(int result) {
  ProcessReadPacket(result);
  ReadPackets();
}

void QuicTransportServerImpl::ProcessReadPacket(int result) {
  if (result == 0)
    result = net::ERR_CONNECTION_CLOSED;
  if (result < 0) {
    LOG(ERROR) << "QuicTransportSimpleServer read failed: "
               << net::ErrorToString(result);
    dispatcher_->Shutdown();
    return;
  }

  ::quic::QuicReceivedPacket packet(read_buffer_->data(), /*length=*/result,
                                    clock_->Now(), /*owns_buffer=*/false);
  dispatcher_->ProcessPacket(net::ToQuicSocketAddress(server_address_),
                             net::ToQuicSocketAddress(client_address_), packet);
}

}  // namespace quic
}  // namespace owt