// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUIC_TRANSPORT_OWT_SERVER_SESSION_H_
#define QUIC_TRANSPORT_OWT_SERVER_SESSION_H_

#include <cstddef>
#include <memory>
#include <string>

#include "net/third_party/quiche/src/quiche/quic/core/quic_session.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_export.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_crypto_server_stream.h"

#include "owt/quic/quic_transport_session_interface.h"
#include "owt/quic_transport/sdk/impl/quic_transport_owt_stream_impl.h"
#include "base/task/single_thread_task_runner.h"

namespace quic {

// A QUIC session with raw stream.
class QUIC_EXPORT_PRIVATE QuicTransportOWTServerSession
    : public QuicSession,
      public owt::quic::QuicTransportSessionInterface {
 public:
  // Does not take ownership of |connection| or |visitor|.
  QuicTransportOWTServerSession(QuicConnection* connection,
                 QuicSession::Visitor* visitor,
                 const QuicConfig& config,
                 const ParsedQuicVersionVector& supported_versions,
                 QuicCryptoServerStream::Helper* helper,
                 const QuicCryptoServerConfig* crypto_config,
                 QuicCompressedCertsCache* compressed_certs_cache,
                 base::SingleThreadTaskRunner* io_runner,
                 base::SingleThreadTaskRunner* event_runner);
  QuicTransportOWTServerSession(const QuicTransportOWTServerSession&) = delete;
  QuicTransportOWTServerSession& operator=(const QuicTransportOWTServerSession&) = delete;

  ~QuicTransportOWTServerSession() override;

  void Initialize() override;

  const QuicCryptoServerStreamBase* crypto_stream() const {
    return crypto_stream_.get();
  }

  void CloseConnectionWithDetails(QuicErrorCode error,
                                  const std::string& details);

  //Implement QuicTransportSessionInterface
  owt::quic::QuicTransportStreamInterface* CreateBidirectionalStream() override;
  void Stop() override;
  void SetVisitor(owt::quic::QuicTransportSessionInterface::Visitor* visitor) override;
  const char* Id() override;
  uint8_t length() override;
  void CloseStream(uint32_t id) override;

 protected:
  // QuicSession methods(override them with return type of QuicSpdyStream*):
  QuicCryptoServerStreamBase* GetMutableCryptoStream() override;

  const QuicCryptoServerStreamBase* GetCryptoStream() const override;

  void OnConnectionClosed(const QuicConnectionCloseFrame& frame,
                          ConnectionCloseSource source) override;

  // Override CreateIncomingStream(), CreateOutgoingBidirectionalStream() and
  // CreateOutgoingUnidirectionalStream() with QuicSpdyStream return type to
  // make sure that all data streams are QuicSpdyStreams.
  QuicTransportOWTStreamImpl* CreateIncomingStream(QuicStreamId id) override;
  QuicTransportOWTStreamImpl* CreateIncomingStream(PendingStream* pending) override;

  virtual owt::quic::QuicTransportStreamInterface* CreateOutgoingBidirectionalStream();
  virtual owt::quic::QuicTransportStreamInterface* CreateOutgoingUnidirectionalStream();

  // If an incoming stream can be created, return true.
  virtual bool ShouldCreateIncomingStream(QuicStreamId id);

  // If an outgoing bidirectional/unidirectional stream can be created, return
  // true.
  virtual bool ShouldCreateOutgoingBidirectionalStream();
  virtual bool ShouldCreateOutgoingUnidirectionalStream();

  // Overridden to buffer incoming streams for version 99.
  bool ShouldBufferIncomingStream(QuicStreamId id) const;


  // Returns true if there are open dynamic streams.
  bool ShouldKeepConnectionAlive() const override;

  //Notify stream closed
  void OnStreamClosed(quic::QuicStreamId stream_id) override;

  bool IsConnected() { return connection()->connected(); }

  virtual std::unique_ptr<QuicCryptoServerStreamBase> CreateQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache);

  const QuicCryptoServerConfig* crypto_config() { return crypto_config_; }

  QuicCryptoServerStream::Helper* stream_helper() { return helper_; }

 private:
 
  // Called when a PRIORITY frame has been received.
  void OnPriority(spdy::SpdyStreamId stream_id, spdy::SpdyPriority priority);

  // Called when the size of the compressed frame payload is available.
  void OnCompressedFrameSize(size_t frame_len);

  QuicTransportOWTStreamImpl* CreateIncomingStreamOnCurrentThread(QuicStreamId id);

  owt::quic::QuicTransportStreamInterface* CreateBidirectionalStreamOnCurrentThread();

  void StopOnCurrentThread();

  void CloseStreamOnCurrentThread(uint32_t id);

  const QuicCryptoServerConfig* crypto_config_;

  // The cache which contains most recently compressed certs.
  // Owned by QuicDispatcher.
  QuicCompressedCertsCache* compressed_certs_cache_;

  std::unique_ptr<QuicCryptoServerStreamBase> crypto_stream_;

  // Pointer to the helper used to create crypto server streams. Must outlive
  // streams created via CreateQuicCryptoServerStream.
  QuicCryptoServerStream::Helper* helper_;

  base::SingleThreadTaskRunner* task_runner_;
  base::SingleThreadTaskRunner* event_runner_;
  owt::quic::QuicTransportSessionInterface::Visitor* visitor_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_HTTP_QUIC_SPDY_SESSION_H_
