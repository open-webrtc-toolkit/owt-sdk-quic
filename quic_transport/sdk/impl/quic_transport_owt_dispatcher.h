// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUIC_TRANSPORT_OWT_DISPATCHER_H_
#define QUIC_TRANSPORT_OWT_DISPATCHER_H_

#include "absl/strings/string_view.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_dispatcher.h"

#include "owt/quic_transport/sdk/impl/quic_transport_owt_server_session.h"
#include "base/task/single_thread_task_runner.h"

namespace quic {

class QuicTransportOwtDispatcher : public QuicDispatcher {
 public:
  // Visitor receives callbacks from the QuicRawDispatcher.
  class QUIC_EXPORT_PRIVATE Visitor {
   public:
    Visitor() {}
    Visitor(const Visitor&) = delete;
    Visitor& operator=(const Visitor&) = delete;

    // Called when new session created
    virtual void OnSessionCreated(QuicTransportOwtServerSession* session) = 0;
    virtual void OnSessionClosed(QuicConnectionId server_connection_id) = 0;

   protected:
    virtual ~Visitor() {}
  };

  QuicTransportOwtDispatcher(
      const QuicConfig* config,
      const QuicCryptoServerConfig* crypto_config,
      QuicVersionManager* version_manager,
      std::unique_ptr<QuicConnectionHelperInterface> helper,
      std::unique_ptr<QuicCryptoServerStream::Helper> session_helper,
      std::unique_ptr<QuicAlarmFactory> alarm_factory,
      uint8_t expected_server_connection_id_length,
      ConnectionIdGeneratorInterface& generator,
      base::SingleThreadTaskRunner* io_runner,
      base::SingleThreadTaskRunner* event_runner);

  ~QuicTransportOwtDispatcher() override;

  //Implement QuicSession::Visitor
  // Called when the connection is closed after the streams have been closed.
  void OnConnectionClosed(QuicConnectionId server_connection_id,
                                    QuicErrorCode error,
                                    const std::string& error_details,
                                    ConnectionCloseSource source) override;

  void set_visitor(Visitor* visitor) { visitor_ = visitor; }

 protected:
  std::unique_ptr<QuicSession> CreateQuicSession(
      QuicConnectionId connection_id,
      const QuicSocketAddress& self_address,
      const QuicSocketAddress& peer_address,
      absl::string_view alpn,
      const ParsedQuicVersion& version,
      const ParsedClientHello& parsed_chlo) override;

 private:
  base::SingleThreadTaskRunner* task_runner_;
  base::SingleThreadTaskRunner* event_runner_;
  Visitor* visitor_;
};

}  // namespace quic

#endif  // QUIC_TRANSPORT_OWT_DISPATCHER_H_
