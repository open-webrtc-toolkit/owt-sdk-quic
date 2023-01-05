// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "owt/quic_transport/sdk/impl/quic_transport_owt_server_session.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>

#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_flag_utils.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_logging.h"

namespace quic {

QuicTransportOwtServerSession::QuicTransportOwtServerSession(
    QuicConnection* connection,
    QuicSession::Visitor* visitor,
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    QuicCryptoServerStream::Helper* helper,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    base::SingleThreadTaskRunner* io_runner,
    base::SingleThreadTaskRunner* event_runner)
    : QuicSession(connection, visitor, config, supported_versions,  0u),
      crypto_config_(crypto_config),
      compressed_certs_cache_(compressed_certs_cache),
      helper_(helper),
      task_runner_(io_runner),
      event_runner_(event_runner),
      visitor_(nullptr) {
}

QuicTransportOwtServerSession::~QuicTransportOwtServerSession() {
  // Set the streams' session pointers in closed and dynamic stream lists
  // to null to avoid subsequent use of this session.
  // for (auto& stream : *closed_streams()) {
  //   static_cast<QuicRawStream*>(stream.get())->ClearSession();
  // }
  // for (auto const& kv : zombie_streams()) {
  //   static_cast<QuicRawStream*>(kv.second.get())->ClearSession();
  // }
  // for (auto const& kv : dynamic_streams()) {
  //   static_cast<QuicRawStream*>(kv.second.get())->ClearSession();
  // }
}

void QuicTransportOwtServerSession::Initialize() {
  crypto_stream_ =
      CreateQuicCryptoServerStream(crypto_config_, compressed_certs_cache_);
  QuicSession::Initialize();
}

QuicCryptoServerStreamBase* QuicTransportOwtServerSession::GetMutableCryptoStream() {
  return crypto_stream_.get();
}

const QuicCryptoServerStreamBase* QuicTransportOwtServerSession::GetCryptoStream()
    const {
  return crypto_stream_.get();
}

void QuicTransportOwtServerSession::OnConnectionClosed(
    const QuicConnectionCloseFrame& frame,
    ConnectionCloseSource source) {
  QuicSession::OnConnectionClosed(frame, source);
  // In the unlikely event we get a connection close while doing an asynchronous
  // crypto event, make sure we cancel the callback.
  if (crypto_stream_ != nullptr) {
    crypto_stream_->CancelOutstandingCallbacks();
  }
}

void QuicTransportOwtServerSession::OnStreamClosed(quic::QuicStreamId stream_id) {
  if (visitor_) {
    visitor_->OnStreamClosed(stream_id);
  }
}

void QuicTransportOwtServerSession::StopOnCurrentThread() {
  connection()->CloseConnection(
        quic::QUIC_PEER_GOING_AWAY, "Shutting down",
        quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

void QuicTransportOwtServerSession::Stop() {
  if (task_runner_->BelongsToCurrentThread()) {
    return StopOnCurrentThread();
  }
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicTransportOwtServerSession::StopOnCurrentThread, base::Unretained(this)));
}

void QuicTransportOwtServerSession::SetVisitor(owt::quic::QuicTransportSessionInterface::Visitor* visitor) { 
  visitor_ = visitor;
}

const char* QuicTransportOwtServerSession::Id() {
  const std::string& session_id_str =
      connection()->connection_id().ToString();
  char* id = new char[session_id_str.size() + 1];
  strcpy(id, session_id_str.c_str());

  return id;
}

void QuicTransportOwtServerSession::CloseStreamOnCurrentThread(uint32_t id) {
  ResetStream(id, QUIC_STREAM_CANCELLED);
}

void QuicTransportOwtServerSession::CloseStream(uint32_t id) {
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicTransportOwtServerSession::CloseStreamOnCurrentThread, base::Unretained(this), id));
}

uint8_t QuicTransportOwtServerSession::length() {
  return connection()->connection_id().length();
}

owt::quic::QuicTransportStreamInterface* QuicTransportOwtServerSession::CreateBidirectionalStream() {
  if (!connection()->connected()) {
    return nullptr;
  }

  auto* stream = static_cast<owt::quic::QuicTransportStreamInterface*>(
      CreateOutgoingBidirectionalStream());
 
  return stream;
}

void QuicTransportOwtServerSession::CloseConnectionWithDetails(QuicErrorCode error,
                                                 const std::string& details) {
  connection()->CloseConnection(
      error, details, ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}


bool QuicTransportOwtServerSession::ShouldCreateIncomingStream(QuicStreamId id) {
  if (!connection()->connected()) {
    QUIC_BUG(quic_bug_10393_1) << "ShouldCreateIncomingStream called when disconnected";
    return false;
  }

  if (QuicUtils::IsServerInitiatedStreamId(connection()->transport_version(),
                                           id)) {
    LOG(ERROR) << "Invalid incoming even stream_id:" << id;
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID, "Client created even numbered stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  return true;
}

bool QuicTransportOwtServerSession::ShouldCreateOutgoingBidirectionalStream() {
  if (!connection()->connected()) {
    QUIC_BUG(quic_bug_12513_2)
        << "ShouldCreateOutgoingBidirectionalStream called when disconnected";
    return false;
  }
  if (!crypto_stream_->encryption_established()) {
    QUIC_BUG(quic_bug_10393_4)
        << "Encryption not established so no outgoing stream created.";
    return false;
  }

  return CanOpenNextOutgoingBidirectionalStream();
}

bool QuicTransportOwtServerSession::ShouldCreateOutgoingUnidirectionalStream() {
  if (!connection()->connected()) {
    QUIC_BUG(quic_bug_12513_3)
        << "ShouldCreateOutgoingUnidirectionalStream called when disconnected";
    return false;
  }
  if (!crypto_stream_->encryption_established()) {
    QUIC_BUG(quic_bug_10393_5)
        << "Encryption not established so no outgoing stream created.";
    return false;
  }

  return CanOpenNextOutgoingUnidirectionalStream();
}

std::unique_ptr<QuicCryptoServerStreamBase>
QuicTransportOwtServerSession::CreateQuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache) {
  return CreateCryptoServerStream(crypto_config, compressed_certs_cache, this,
                                  stream_helper());
}

QuicTransportOwtStreamImpl* QuicTransportOwtServerSession::CreateIncomingStreamOnCurrentThread(QuicStreamId id) {
  if (!ShouldCreateIncomingStream(id)) {
    return nullptr;
  }

  QuicTransportOwtStreamImpl* stream = new QuicTransportOwtStreamImpl(
      id, this, BIDIRECTIONAL, task_runner_, event_runner_);
  ActivateStream(absl::WrapUnique(stream));
  if (visitor_) {
    visitor_->OnIncomingStream(stream);
  }
  return stream;
}


QuicTransportOwtStreamImpl* QuicTransportOwtServerSession::CreateIncomingStream(QuicStreamId id) {
  QuicTransportOwtStreamImpl* result(nullptr);
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  event_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](QuicTransportOwtServerSession* session,
             QuicStreamId& id,
             QuicTransportOwtStreamImpl** result, base::WaitableEvent* event) {
            *result = session->CreateIncomingStreamOnCurrentThread(id);
            event->Signal();
          },
          base::Unretained(this), std::ref(id), base::Unretained(&result),
          base::Unretained(&done)));
  done.Wait();
  return result;
}

QuicTransportOwtStreamImpl* QuicTransportOwtServerSession::CreateIncomingStream(
    PendingStream* pending) {
  QuicTransportOwtStreamImpl* stream = new QuicTransportOwtStreamImpl(
      pending, this, BIDIRECTIONAL, task_runner_, event_runner_);
  ActivateStream(absl::WrapUnique(stream));
  if (visitor_) {
    visitor_->OnIncomingStream(stream);
  }
  return stream;
}

// QuicRawStream* QuicRawServerSession::CreateIncomingStream(
//     PendingStream pending) {
//   QuicRawStream* stream = new QuicRawStream(
//       std::move(pending), this, BIDIRECTIONAL);
//   ActivateStream(QuicWrapUnique(stream));
//   return stream;
// }

owt::quic::QuicTransportStreamInterface*
QuicTransportOwtServerSession::CreateOutgoingBidirectionalStream() {
  
  owt::quic::QuicTransportStreamInterface* result(nullptr);
  base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                           base::WaitableEvent::InitialState::NOT_SIGNALED);
  event_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](QuicTransportOwtServerSession* session,
             owt::quic::QuicTransportStreamInterface** result, base::WaitableEvent* event) {
            *result = session->CreateBidirectionalStreamOnCurrentThread();
            event->Signal();
          },
          base::Unretained(this), base::Unretained(&result),
          base::Unretained(&done)));
  done.Wait();
  return result;

}

owt::quic::QuicTransportStreamInterface*
QuicTransportOwtServerSession::CreateBidirectionalStreamOnCurrentThread() {
  if (!ShouldCreateOutgoingBidirectionalStream()) {
    return nullptr;
  }

  std::unique_ptr<QuicTransportOwtStreamImpl> stream =
        std::make_unique<QuicTransportOwtStreamImpl>(GetNextOutgoingBidirectionalStreamId(),
                                        this, BIDIRECTIONAL, task_runner_, event_runner_);
    owt::quic::QuicTransportStreamInterface* stream_ptr = stream.get();
    ActivateStream(std::move(stream));

  return stream_ptr;
}

owt::quic::QuicTransportStreamInterface*
QuicTransportOwtServerSession::CreateOutgoingUnidirectionalStream() {
  if (!ShouldCreateOutgoingUnidirectionalStream()) {
    return nullptr;
  }

  std::unique_ptr<QuicTransportOwtStreamImpl> stream =
        std::make_unique<QuicTransportOwtStreamImpl>(GetNextOutgoingUnidirectionalStreamId(),
                                        this, WRITE_UNIDIRECTIONAL, task_runner_, event_runner_);
    owt::quic::QuicTransportStreamInterface* stream_ptr = stream.get();
    ActivateStream(std::move(stream));

  return stream_ptr;
}

// True if there are open dynamic streams.
bool QuicTransportOwtServerSession::ShouldKeepConnectionAlive() const {
  //return GetNumOpenDynamicStreams() > 0;
  return true;
}

}  // namespace quic
