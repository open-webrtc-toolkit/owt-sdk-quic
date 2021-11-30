// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "owt/quic_transport/sdk/impl/quic_transport_owt_server_session.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>

#include "net/third_party/quiche/src/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flag_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"

namespace quic {

QuicTransportOWTServerSession::QuicTransportOWTServerSession(
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

QuicTransportOWTServerSession::~QuicTransportOWTServerSession() {
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
  delete connection();
}

void QuicTransportOWTServerSession::Initialize() {
  crypto_stream_ =
      CreateQuicCryptoServerStream(crypto_config_, compressed_certs_cache_);
  QuicSession::Initialize();
}

QuicCryptoServerStreamBase* QuicTransportOWTServerSession::GetMutableCryptoStream() {
  return crypto_stream_.get();
}

const QuicCryptoServerStreamBase* QuicTransportOWTServerSession::GetCryptoStream()
    const {
  return crypto_stream_.get();
}

void QuicTransportOWTServerSession::OnConnectionClosed(
    const QuicConnectionCloseFrame& frame,
    ConnectionCloseSource source) {
  QuicSession::OnConnectionClosed(frame, source);
  // In the unlikely event we get a connection close while doing an asynchronous
  // crypto event, make sure we cancel the callback.
  if (crypto_stream_ != nullptr) {
    crypto_stream_->CancelOutstandingCallbacks();
  }
}

void QuicTransportOWTServerSession::SetVisitor(QuicTransportSessionInterface::Visitor* visitor) { 
  visitor_ = visitor;
}

std::string id() {
  return connection()->connection_id().ToString();
}

quic::QuicTransportStreamInterface* QuicTransportOWTServerSession::CreateBidirectionalStream() {
  if (!connection()->connected()) {
    return nullptr;
  }

  auto* stream = static_cast<quic::QuicTransportStreamInterface*>(
      CreateOutgoingBidirectionalStream());
 
  return stream;
}

void QuicTransportOWTServerSession::CloseConnectionWithDetails(QuicErrorCode error,
                                                 const std::string& details) {
  connection()->CloseConnection(
      error, details, ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}


bool QuicTransportOWTServerSession::ShouldCreateIncomingStream(QuicStreamId id) {
  if (!connection()->connected()) {
    QUIC_BUG(quic_bug_10393_1) << "ShouldCreateIncomingStream called when disconnected";
    return false;
  }

  if (QuicUtils::IsServerInitiatedStreamId(connection()->transport_version(),
                                           id)) {
    QUIC_DLOG(INFO) << "Invalid incoming even stream_id:" << id;
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID, "Client created even numbered stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  return true;
}

bool QuicTransportOWTServerSession::ShouldCreateOutgoingBidirectionalStream() {
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

bool QuicTransportOWTServerSession::ShouldCreateOutgoingUnidirectionalStream() {
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
QuicTransportOWTServerSession::CreateQuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache) {
  return CreateCryptoServerStream(crypto_config, compressed_certs_cache, this,
                                  stream_helper());
}

QuicTransportOWTStreamImpl* QuicTransportOWTServerSession::CreateIncomingStream(QuicStreamId id) {
  if (!ShouldCreateIncomingStream(id)) {
    return nullptr;
  }

  QuicTransportOWTStreamImpl* stream = new QuicTransportOWTStreamImpl(
      id, this, BIDIRECTIONAL, task_runner_, event_runner_);
  ActivateStream(absl::WrapUnique(stream));
  if (visitor_) {
    visitor_->OnIncomingStream(this, stream);
  }
  return stream;
}

QuicTransportOWTStreamImpl* QuicTransportOWTServerSession::CreateIncomingStream(
    PendingStream* pending) {
  QuicTransportOWTStreamImpl* stream = new QuicTransportOWTStreamImpl(
      pending, this, BIDIRECTIONAL, task_runner_, event_runner_);
  ActivateStream(absl::WrapUnique(stream));
  if (visitor_) {
    visitor_->OnIncomingStream(this, stream);
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

QuicTransportStreamInterface*
QuicTransportOWTServerSession::CreateOutgoingBidirectionalStream() {
  if (!ShouldCreateOutgoingBidirectionalStream()) {
    return nullptr;
  }

  std::unique_ptr<QuicTransportOWTStreamImpl> stream =
        std::make_unique<QuicTransportOWTStreamImpl>(GetNextOutgoingBidirectionalStreamId(),
                                        this, BIDIRECTIONAL, task_runner_, event_runner_);
    QuicTransportStreamInterface* stream_ptr = stream.get();
    ActivateStream(std::move(stream));

  return stream_ptr;
}

QuicTransportStreamInterface*
QuicTransportOWTServerSession::CreateOutgoingUnidirectionalStream() {
  if (!ShouldCreateOutgoingUnidirectionalStream()) {
    return nullptr;
  }

  std::unique_ptr<QuicTransportOWTStreamImpl> stream =
        std::make_unique<QuicTransportOWTStreamImpl>(GetNextOutgoingUnidirectionalStreamId(),
                                        this, WRITE_UNIDIRECTIONAL, task_runner_, event_runner_);
    QuicTransportStreamInterface* stream_ptr = stream.get();
    ActivateStream(std::move(stream));

  return stream_ptr;
}

// True if there are open dynamic streams.
bool QuicTransportOWTServerSession::ShouldKeepConnectionAlive() const {
  //return GetNumOpenDynamicStreams() > 0;
  return true;
}

}  // namespace quic
