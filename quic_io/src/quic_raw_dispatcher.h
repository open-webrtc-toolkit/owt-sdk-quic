// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_RAW_QUIC_RAW_DISPATCHER_H_
#define NET_TOOLS_QUIC_RAW_QUIC_RAW_DISPATCHER_H_

#include "absl/strings/string_view.h"
#include "net/third_party/quiche/src/quic/core/quic_dispatcher.h"

#include "net/tools/quic/raw/quic_raw_server_session.h"

namespace quic {

class QuicRawDispatcher : public QuicDispatcher {
 public:
  // Visitor receives callbacks from the QuicRawDispatcher.
  class QUIC_EXPORT_PRIVATE Visitor {
   public:
    Visitor() {}
    Visitor(const Visitor&) = delete;
    Visitor& operator=(const Visitor&) = delete;

    // Called when new session created
    virtual void OnSessionCreated(QuicRawServerSession* session) = 0;
    virtual void OnSessionClosed(QuicRawServerSession* session) = 0;

   protected:
    virtual ~Visitor() {}
  };

  QuicRawDispatcher(
      const QuicConfig* config,
      const QuicCryptoServerConfig* crypto_config,
      QuicVersionManager* version_manager,
      std::unique_ptr<QuicConnectionHelperInterface> helper,
      std::unique_ptr<QuicCryptoServerStream::Helper> session_helper,
      std::unique_ptr<QuicAlarmFactory> alarm_factory,
      uint8_t expected_server_connection_id_length);

  ~QuicRawDispatcher() override;

  void set_visitor(Visitor* visitor) { visitor_ = visitor; }

 protected:
  std::unique_ptr<QuicSession> CreateQuicSession(
      QuicConnectionId connection_id,
      const QuicSocketAddress& self_address,
      const QuicSocketAddress& peer_address,
      absl::string_view alpn,
      const ParsedQuicVersion& version,
      absl::string_view sni) override;

 private:
  // The map of the reset error code with its counter.
  Visitor* visitor_;
};

}  // namespace quic

#endif  // NET_TOOLS_QUIC_RAW_QUIC_RAW_DISPATCHER_H_
