// A client transport raw data on QUIC

#ifndef QUIC_TRANSPORT_OWT_CLIENT_IMPL_H_
#define QUIC_TRANSPORT_OWT_CLIENT_IMPL_H_

#include <stddef.h>

#include <memory>
#include <string>

#include "base/command_line.h"
#include "base/macros.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/third_party/quiche/src/quic/core/http/quic_spdy_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_config.h"
#include "net/tools/quic/quic_client_message_loop_network_helper.h"

#include "owt/quic_transport/sdk/impl/quic_transport_owt_client_base.h"
#include "owt/quic/quic_transport_client_interface.h"
#include "owt/quic/quic_transport_stream_interface.h"
#include "owt/quic_transport/sdk/impl/proof_verifier_owt.h"
#include "base/threading/thread.h"

namespace net {

class QuicChromiumAlarmFactory;
class QuicChromiumConnectionHelper;

class QuicTransportOWTClientImpl : public quic::QuicTransportOWTClientBase,
                                   public quic::QuicTransportOWTClientSession::Visitor,
                                   public owt::quic::QuicTransportClientInterface {
 public:

  // Create a quic client, which will have events managed by the message loop.
  QuicTransportOWTClientImpl(quic::QuicSocketAddress server_address,
                   const quic::QuicServerId& server_id,
                   const quic::ParsedQuicVersionVector& supported_versions,
                   std::unique_ptr<quic::ProofVerifier> proof_verifier,
                   base::Thread* io_thread,
                   base::Thread* event_thread);

  ~QuicTransportOWTClientImpl() override;

  int SocketPort();
  void Start() override;
  void Stop() override;
  void SetVisitor(owt::quic::QuicTransportClientInterface::Visitor* visitor) override;
  owt::quic::QuicTransportStreamInterface* CreateBidirectionalStream() override;
  void OnConnectionClosed(char*, size_t len) override;
  void OnIncomingNewStream(quic::QuicTransportOWTStreamImpl* stream) override;
  void OnStreamClosed(uint32_t id) override;
  const char* Id() override;
  uint8_t length() override;

 private:

  QuicChromiumAlarmFactory* CreateQuicAlarmFactory();
  QuicChromiumConnectionHelper* CreateQuicConnectionHelper();
  QuicClientMessageLooplNetworkHelper* CreateNetworkHelper();
  void StartOnCurrentThread();
  void StopOnCurrentThread();

  owt::quic::QuicTransportStreamInterface* CreateBidirectionalStreamOnCurrentThread();
  //  Used by |helper_| to time alarms.
  quic::QuicChromiumClock clock_;

  QuicClientMessageLooplNetworkHelper* created_helper_;
  std::unique_ptr<base::Thread> io_thread_owned_;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> event_runner_;
  QuicTransportClientInterface::Visitor* visitor_;
  quic::QuicTransportOWTClientSession* session_;

  base::WeakPtrFactory<QuicTransportOWTClientImpl> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(QuicTransportOWTClientImpl);
};

}  // namespace net

#endif  // QUIC_TRANSPORT_OWT_CLIENT_IMPL_H_
