/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_WEB_TRANSPORT_HTTP3_SERVER_SESSION_H_
#define OWT_QUIC_WEB_TRANSPORT_HTTP3_SERVER_SESSION_H_

#include "base/task/single_thread_task_runner.h"
#include "net/third_party/quiche/src/quic/core/http/quic_server_session_base.h"

namespace owt {
namespace quic {

class WebTransportServerBackend;

class Http3ServerSession : public ::quic::QuicServerSessionBase {
 public:
  explicit Http3ServerSession(
      const ::quic::QuicConfig& config,
      const ::quic::ParsedQuicVersionVector& supported_versions,
      ::quic::QuicConnection* connection,
      ::quic::QuicSession::Visitor* visitor,
      ::quic::QuicCryptoServerStreamBase::Helper* helper,
      const ::quic::QuicCryptoServerConfig* crypto_config,
      ::quic::QuicCompressedCertsCache* compressed_certs_cache,
      WebTransportServerBackend* backend,
      base::SingleThreadTaskRunner* io_runner,
      base::SingleThreadTaskRunner* event_runner);
  ~Http3ServerSession() override;
  Http3ServerSession& operator=(Http3ServerSession&) = delete;

 protected:
  // Override ::quic::QuicServerSessionBase.
  ::quic::QuicSpdyStream* CreateIncomingStream(
      ::quic::QuicStreamId id) override;
  ::quic::QuicSpdyStream* CreateIncomingStream(
      ::quic::PendingStream* pending) override;
  ::quic::QuicSpdyStream* CreateOutgoingBidirectionalStream() override;
  ::quic::QuicSpdyStream* CreateOutgoingUnidirectionalStream() override;
  std::unique_ptr<::quic::QuicCryptoServerStreamBase>
  CreateQuicCryptoServerStream(
      const ::quic::QuicCryptoServerConfig* crypto_config,
      ::quic::QuicCompressedCertsCache* compressed_certs_cache) override;

  // Overrides QuicSpdySession.
  bool ShouldNegotiateWebTransport() override;
  ::quic::HttpDatagramSupport LocalHttpDatagramSupport() override;

 private:
  WebTransportServerBackend* backend_;
  base::SingleThreadTaskRunner* io_runner_;
  base::SingleThreadTaskRunner* event_runner_;
};

}  // namespace quic
}  // namespace owt

#endif