// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/raw/quic_raw_server_session.h"

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

QuicRawServerSession::QuicRawServerSession(
    QuicConnection* connection,
    QuicSession::Visitor* visitor,
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    QuicCryptoServerStream::Helper* helper,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache)
    : QuicSession(connection, visitor, config, supported_versions,  0u),
      crypto_config_(crypto_config),
      compressed_certs_cache_(compressed_certs_cache),
      helper_(helper),
      visitor_(nullptr) {
}

QuicRawServerSession::~QuicRawServerSession() {
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

void QuicRawServerSession::Initialize() {
  crypto_stream_ =
      CreateQuicCryptoServerStream(crypto_config_, compressed_certs_cache_);
  QuicSession::Initialize();
}

QuicCryptoServerStreamBase* QuicRawServerSession::GetMutableCryptoStream() {
  return crypto_stream_.get();
}

const QuicCryptoServerStreamBase* QuicRawServerSession::GetCryptoStream()
    const {
  return crypto_stream_.get();
}

void QuicRawServerSession::OnConnectionClosed(
    const QuicConnectionCloseFrame& frame,
    ConnectionCloseSource source) {
  QuicSession::OnConnectionClosed(frame, source);
  // In the unlikely event we get a connection close while doing an asynchronous
  // crypto event, make sure we cancel the callback.
  if (crypto_stream_ != nullptr) {
    crypto_stream_->CancelOutstandingCallbacks();
  }
}

void QuicRawServerSession::CloseConnectionWithDetails(QuicErrorCode error,
                                                 const std::string& details) {
  connection()->CloseConnection(
      error, details, ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}


bool QuicRawServerSession::ShouldCreateIncomingStream(QuicStreamId id) {
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

bool QuicRawServerSession::ShouldCreateOutgoingBidirectionalStream() {
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

bool QuicRawServerSession::ShouldCreateOutgoingUnidirectionalStream() {
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
QuicRawServerSession::CreateQuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache) {
  return CreateCryptoServerStream(crypto_config, compressed_certs_cache, this,
                                  stream_helper());
}

QuicRawStream* QuicRawServerSession::CreateIncomingStream(QuicStreamId id) {
  if (!ShouldCreateIncomingStream(id)) {
    return nullptr;
  }

  QuicRawStream* stream = new QuicRawStream(
      id, this, BIDIRECTIONAL);
  ActivateStream(absl::WrapUnique(stream));
  if (visitor_) {
    visitor_->OnIncomingStream(this, stream);
  }
  return stream;
}

QuicRawStream* QuicRawServerSession::CreateIncomingStream(
    PendingStream* pending) {
  QuicRawStream* stream = new QuicRawStream(
      pending, this, BIDIRECTIONAL);
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

QuicRawStream*
QuicRawServerSession::CreateOutgoingBidirectionalStream() {
  DCHECK(false);
  return nullptr;
}

QuicRawStream*
QuicRawServerSession::CreateOutgoingUnidirectionalStream() {
  if (!ShouldCreateOutgoingUnidirectionalStream()) {
    return nullptr;
  }

  QuicRawStream* stream = new QuicRawStream(
      GetNextOutgoingUnidirectionalStreamId(), this, WRITE_UNIDIRECTIONAL);
  ActivateStream(absl::WrapUnique(stream));
  return stream;
}

// True if there are open dynamic streams.
bool QuicRawServerSession::ShouldKeepConnectionAlive() const {
  //return GetNumOpenDynamicStreams() > 0;
  return true;
}

}  // namespace quic
