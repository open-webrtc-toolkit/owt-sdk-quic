/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Most classes in this file and its implementations are borrowed from
// Chromium/net/tools/quic/quic_transport_simple_server.h
// with modifications.

#ifndef OWT_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_OWT_SERVER_IMPL_H_
#define OWT_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_OWT_SERVER_IMPL_H_

#include <string>
#include <vector>
#include "base/memory/scoped_refptr.h"
#include "base/single_thread_task_runner.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/socket/udp_server_socket.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_crypto_server_config.h"
#include "net/third_party/quiche/src/quic/core/quic_config.h"
#include "net/third_party/quiche/src/quic/core/quic_version_manager.h"
#include "net/third_party/quiche/src/quic/tools/quic_transport_simple_server_dispatcher.h"
#include "owt/quic/quic_transport_server_interface.h"
#include "owt/quic_transport/impl/quic_transport_owt_server_dispatcher.h"
#include "url/origin.h"

namespace owt {
namespace quic {
// A server accepts WebTransport - QuicTransport connections.
class QuicTransportOwtServerImpl : public QuicTransportServerInterface,
                                   public QuicTransportOwtServerDispatcher::Visitor {
 public:
  QuicTransportOwtServerImpl() = delete;
  explicit QuicTransportOwtServerImpl(
      int port,
      std::vector<url::Origin> accepted_origins,
      std::unique_ptr<::quic::ProofSource> proof_source,
      base::Thread* io_thread,
      base::Thread* event_thread);
  ~QuicTransportOwtServerImpl() override;
  int Start() override;
  void Stop() override;
  void SetVisitor(QuicTransportServerInterface::Visitor* visitor) override;

 protected:
  // Implements QuicTransportOwtServerDispatcher::Visitor.
  void OnSession(QuicTransportOwtServerSession* session) override;

 private:
  // Schedules a ReadPackets() call on the next iteration of the event loop.
  void ScheduleReadPackets();
  // Reads a fixed number of packets and then reschedules itself.
  void ReadPackets();
  // Called when an asynchronous read from the socket is complete.
  void OnReadComplete(int result);
  // Passes the most recently read packet into the dispatcher.
  void ProcessReadPacket(int result);

  void StartOnCurrentThread(base::WaitableEvent* done);

 private:
  const int port_;
  ::quic::QuicVersionManager version_manager_;
  ::quic::QuicChromiumClock* clock_;  // Not owned.
  ::quic::QuicConfig config_;
  ::quic::QuicCryptoServerConfig crypto_config_;

  std::unique_ptr<QuicTransportOwtServerDispatcher> dispatcher_;
  std::unique_ptr<net::UDPServerSocket> socket_;
  net::IPEndPoint server_address_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> event_runner_;

  // Results of the potentially asynchronous read operation.
  scoped_refptr<net::IOBufferWithSize> read_buffer_;
  net::IPEndPoint client_address_;

  QuicTransportServerInterface::Visitor* visitor_;

  base::WeakPtrFactory<QuicTransportOwtServerImpl> weak_factory_{this};
};
}  // namespace quic
}  // namespace owt

#endif