/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Some implementations are borrowed from
// Chromium/net/third_party/quiche/src/quic/tools/quic_simple_server_session.cc
// with modifications.

#include "impl/http3_server_session.h"
#include "impl/http3_server_stream.h"
#include "net/third_party/quiche/src/quic/core/http/quic_server_initiated_spdy_stream.h"

namespace owt {
namespace quic {

Http3ServerSession::Http3ServerSession(
    const ::quic::QuicConfig& config,
    const ::quic::ParsedQuicVersionVector& supported_versions,
    ::quic::QuicConnection* connection,
    ::quic::QuicSession::Visitor* visitor,
    ::quic::QuicCryptoServerStreamBase::Helper* helper,
    const ::quic::QuicCryptoServerConfig* crypto_config,
    ::quic::QuicCompressedCertsCache* compressed_certs_cache,
    base::SingleThreadTaskRunner* io_runner,
    base::SingleThreadTaskRunner* event_runner)
    : QuicServerSessionBase(config,
                            supported_versions,
                            connection,
                            visitor,
                            helper,
                            crypto_config,
                            compressed_certs_cache),
      io_runner_(io_runner),
      event_runner_(event_runner) {
  CHECK(io_runner_);
  CHECK(event_runner_);
}

::quic::QuicSpdyStream* Http3ServerSession::CreateIncomingStream(
    ::quic::QuicStreamId id) {
  if (!ShouldCreateIncomingStream(id)) {
    return nullptr;
  }
  std::unique_ptr<::quic::QuicSpdyStream> stream =
      std::make_unique<Http3ServerStream>(id, this,
                                          ::quic::StreamType::BIDIRECTIONAL,
                                          io_runner_, event_runner_);
  ::quic::QuicSpdyStream* stream_ptr = stream.get();
  ActivateStream(std::move(stream));
  return stream_ptr;
}

::quic::QuicSpdyStream* Http3ServerSession::CreateIncomingStream(
    ::quic::PendingStream* pending) {
  std::unique_ptr<::quic::QuicSpdyStream> stream =
      std::make_unique<Http3ServerStream>(pending, this,
                                          ::quic::StreamType::BIDIRECTIONAL,
                                          io_runner_, event_runner_);
  ::quic::QuicSpdyStream* stream_ptr = stream.get();
  ActivateStream(std::move(stream));
  return stream_ptr;
}

::quic::QuicSpdyStream*
Http3ServerSession::CreateOutgoingBidirectionalStream() {
  if (!WillNegotiateWebTransport()) {
    LOG(ERROR)
        << "CreateOutgoingBidirectionalStream willout WebTransport support.";
    return nullptr;
  }
  if (!ShouldCreateOutgoingBidirectionalStream()) {
    return nullptr;
  }

  ::quic::QuicServerInitiatedSpdyStream* stream =
      new ::quic::QuicServerInitiatedSpdyStream(
          GetNextOutgoingBidirectionalStreamId(), this, ::quic::BIDIRECTIONAL);
  ActivateStream(absl::WrapUnique(stream));
  return stream;
}

::quic::QuicSpdyStream*
Http3ServerSession::CreateOutgoingUnidirectionalStream() {
  if (!ShouldCreateOutgoingUnidirectionalStream()) {
    return nullptr;
  }

  std::unique_ptr<::quic::QuicSpdyStream> stream =
      std::make_unique<Http3ServerStream>(
          GetNextOutgoingUnidirectionalStreamId(), this,
          ::quic::StreamType::WRITE_UNIDIRECTIONAL, io_runner_, event_runner_);
  ::quic::QuicSpdyStream* stream_ptr = stream.get();
  ActivateStream(std::move(stream));
  return stream_ptr;
}

std::unique_ptr<::quic::QuicCryptoServerStreamBase>
Http3ServerSession::CreateQuicCryptoServerStream(
    const ::quic::QuicCryptoServerConfig* crypto_config,
    ::quic::QuicCompressedCertsCache* compressed_certs_cache) {
  return CreateCryptoServerStream(crypto_config, compressed_certs_cache, this,
                                  stream_helper());
}

}  // namespace quic
}  // namespace owt