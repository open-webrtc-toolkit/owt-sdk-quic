// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "owt/quic_transport/sdk/impl/quic_transport_owt_client_impl.h"

#include <utility>

#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/net_errors.h"
#include "net/quic/address_utils.h"
#include "net/base/privacy_mode.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_info.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_with_source.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/quic/quic_chromium_packet_writer.h"
#include "net/socket/udp_client_socket.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_random.h"
#include "net/third_party/quiche/src/quic/core/http/spdy_utils.h"
#include "net/third_party/quiche/src/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/tools/quic_simple_client_session.h"
#include "net/third_party/quiche/src/spdy/core/spdy_header_block.h"

using std::string;

namespace net {

QuicTransportOWTClientImpl::QuicTransportOWTClientImpl(
    quic::QuicSocketAddress server_address,
    const quic::QuicServerId& server_id,
    const quic::ParsedQuicVersionVector& supported_versions,
    std::unique_ptr<quic::ProofVerifier> proof_verifier,
    base::Thread* io_thread,
    base::Thread* event_thread)
    : quic::QuicTransportOWTClientBase(
          server_id,
          supported_versions,
          quic::QuicConfig(),
          CreateQuicConnectionHelper(),
          CreateQuicAlarmFactory(),
          base::WrapUnique(CreateNetworkHelper()),
          std::move(proof_verifier),
          nullptr,
          io_thread->task_runner().get(),
          event_thread->task_runner().get()),
      event_runner_(event_thread->task_runner()),
      weak_factory_(this) {
  if (!io_thread) {
    LOG(INFO) << "Create a new IO stream.";
    io_thread_owned_ =
        std::make_unique<base::Thread>("quic_transport_client_io_thread");
    base::Thread::Options options;
    options.message_pump_type = base::MessagePumpType::IO;
    io_thread_owned_->StartWithOptions(options);
    task_runner_ = io_thread_owned_->task_runner();
  } else {
    task_runner_ = io_thread->task_runner();
  }
  set_server_address(server_address);
}

QuicTransportOWTClientImpl::~QuicTransportOWTClientImpl() {
  if (connected()) {
    session()->connection()->CloseConnection(
        quic::QUIC_PEER_GOING_AWAY, "Shutting down",
        quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
}

QuicChromiumConnectionHelper* QuicTransportOWTClientImpl::CreateQuicConnectionHelper() {
  return new QuicChromiumConnectionHelper(&clock_,
                                          quic::QuicRandom::GetInstance());
}

QuicClientMessageLooplNetworkHelper* QuicTransportOWTClientImpl::CreateNetworkHelper() {
  created_helper_ = new QuicClientMessageLooplNetworkHelper(&clock_, this);
  return created_helper_;
}

void QuicTransportOWTClientImpl::Start() {
  if (!Initialize()) {
      std::cerr << "Failed to initialize client." << std::endl;
      return;
    }
    if (!Connect()) {
      std::cerr << "Failed to connect." << std::endl;
      return;
    }

    std::cerr << "client connect to quic server succeed" << std::endl;
    session_ = client_session();
    session_->set_visitor(this);
}

void QuicTransportOWTClientImpl::Stop() {
  
}

int QuicTransportOWTClientImpl::SocketPort() {
  return created_helper_->GetLatestClientAddress().port();
}

void QuicTransportOWTClientImpl::SetVisitor(QuicTransportClientInterface::Visitor* visitor) {
  visitor_ = visitor;
}

void QuicTransportOWTClientImpl::OnIncomingNewStream(quic::QuicTransportOWTStreamImpl* stream) {
  if(visitor_) {
    visitor_->OnIncomingStream(stream);
  }
}

quic::QuicTransportStreamInterface* QuicTransportOWTClientImpl::CreateBidirectionalStream() {
  if (!connected()) {
    return nullptr;
  }

  auto* stream = static_cast<quic::QuicTransportStreamInterface*>(
      client_session()->CreateOutgoingBidirectionalStream());
 
  return stream;
}

QuicChromiumAlarmFactory* QuicTransportOWTClientImpl::CreateQuicAlarmFactory() {
  return new QuicChromiumAlarmFactory(base::ThreadTaskRunnerHandle::Get().get(),
                                      &clock_);
}

}  // namespace quic
