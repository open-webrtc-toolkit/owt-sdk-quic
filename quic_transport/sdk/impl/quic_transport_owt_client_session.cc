
#include "owt/quic_transport/sdk/impl/quic_transport_owt_client_session.h"

#include <string>

#include "net/third_party/quiche/src/quic/core/crypto/crypto_protocol.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flag_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"

namespace quic {

QuicTransportOWTClientSession::QuicTransportOWTClientSession(
    QuicConnection* connection,
    QuicSession::Visitor* visitor,
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    const QuicServerId& server_id,
    QuicCryptoClientConfig* crypto_config,
    base::SingleThreadTaskRunner* io_runner,
    base::SingleThreadTaskRunner* event_runner)
    : QuicSession(connection, visitor, config, supported_versions, 0u),
      server_id_(server_id),
      crypto_config_(crypto_config),
      task_runner_(io_runner),
      event_runner_(event_runner),
      respect_goaway_(false) {}

QuicTransportOWTClientSession::~QuicTransportOWTClientSession() = default;

void QuicTransportOWTClientSession::Initialize() {
  crypto_stream_ = CreateQuicCryptoStream();
  QuicSession::Initialize();
}

void QuicTransportOWTClientSession::OnProofValid(
    const QuicCryptoClientConfig::CachedState& /*cached*/) {}

void QuicTransportOWTClientSession::OnProofVerifyDetailsAvailable(
    const ProofVerifyDetails& /*verify_details*/) {}

bool QuicTransportOWTClientSession::ShouldCreateOutgoingBidirectionalStream() {
  if (!crypto_stream_->encryption_established()) {
    QUIC_DLOG(INFO) << "Encryption not active so no outgoing stream created.";
    return false;
  }
  // if (!GetQuicReloadableFlag(quic_use_common_stream_check) &&
  //     connection()->transport_version() != QUIC_VERSION_99) {
  //   if (GetNumOpenOutgoingStreams() >=
  //       stream_id_manager().max_open_outgoing_streams()) {
  //     QUIC_DLOG(INFO) << "Failed to create a new outgoing stream. "
  //                     << "Already " << GetNumOpenOutgoingStreams() << " open.";
  //     return false;
  //   }
  //   if (goaway_received() && respect_goaway_) {
  //     QUIC_DLOG(INFO) << "Failed to create a new outgoing stream. "
  //                     << "Already received goaway.";
  //     return false;
  //   }
  //   return true;
  // }
  // if (goaway_received() && respect_goaway_) {
  //   QUIC_DLOG(INFO) << "Failed to create a new outgoing stream. "
  //                   << "Already received goaway.";
  //   return false;
  // }
  // QUIC_RELOADABLE_FLAG_COUNT_N(quic_use_common_stream_check, 1, 2);
  // return CanOpenNextOutgoingBidirectionalStream();
  return true;
}

bool QuicTransportOWTClientSession::ShouldCreateOutgoingUnidirectionalStream() {
  QUIC_BUG(quic_bug_10396_1) << "Try to create outgoing unidirectional client data streams";
  return false;
}

owt::quic::QuicTransportStreamInterface*
QuicTransportOWTClientSession::CreateOutgoingBidirectionalStream() {
  if (!ShouldCreateOutgoingBidirectionalStream()) {
    return nullptr;
  }
  std::unique_ptr<QuicTransportOWTStreamImpl> stream =
        std::make_unique<QuicTransportOWTStreamImpl>(GetNextOutgoingBidirectionalStreamId(),
                                        this, BIDIRECTIONAL, task_runner_, event_runner_);
  owt::quic::QuicTransportStreamInterface* stream_ptr = stream.get();
  ActivateStream(std::move(stream));
  return stream_ptr;
}

owt::quic::QuicTransportStreamInterface*
QuicTransportOWTClientSession::CreateOutgoingUnidirectionalStream() {
  QUIC_BUG(quic_bug_10396_2) << "Try to create outgoing unidirectional client data streams";
  return nullptr;
}

QuicCryptoClientStreamBase* QuicTransportOWTClientSession::GetMutableCryptoStream() {
  return crypto_stream_.get();
}

const QuicCryptoClientStreamBase* QuicTransportOWTClientSession::GetCryptoStream()
    const {
  return crypto_stream_.get();
}

void QuicTransportOWTClientSession::CryptoConnect() {
  DCHECK(flow_controller());
  crypto_stream_->CryptoConnect();
}

int QuicTransportOWTClientSession::GetNumSentClientHellos() const {
  return crypto_stream_->num_sent_client_hellos();
}

int QuicTransportOWTClientSession::GetNumReceivedServerConfigUpdates() const {
  return crypto_stream_->num_scup_messages_received();
}

bool QuicTransportOWTClientSession::EarlyDataAccepted() const {
  return crypto_stream_->EarlyDataAccepted();
}

bool QuicTransportOWTClientSession::ReceivedInchoateReject() const {
  return crypto_stream_->ReceivedInchoateReject();
}

bool QuicTransportOWTClientSession::ShouldCreateIncomingStream(QuicStreamId id) {
  if (!connection()->connected()) {
    QUIC_BUG(quic_bug_10396_3) << "ShouldCreateIncomingStream called when disconnected";
    return false;
  }
  if (transport_goaway_received() && respect_goaway_) {
    QUIC_DLOG(INFO) << "Failed to create a new outgoing stream. "
                    << "Already received goaway.";
    return false;
  }
  // if (QuicUtils::IsClientInitiatedStreamId(connection()->transport_version(),
  //                                          id) ||
  //     (connection()->transport_version() == QUIC_VERSION_99 &&
  //      QuicUtils::IsBidirectionalStreamId(id))) {
  //   QUIC_LOG(WARNING) << "Received invalid push stream id " << id;
  //   connection()->CloseConnection(
  //       QUIC_INVALID_STREAM_ID,
  //       "Server created non write unidirectional stream",
  //       ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  //   return false;
  // }
  return true;
}

QuicTransportOWTStreamImpl* QuicTransportOWTClientSession::CreateIncomingStream(QuicStreamId id) {
  if (!ShouldCreateIncomingStream(id)) {
    return nullptr;
  }

  QuicTransportOWTStreamImpl* stream = new QuicTransportOWTStreamImpl(
      id, this, BIDIRECTIONAL, task_runner_, event_runner_);
  ActivateStream(absl::WrapUnique(stream));
  if (visitor_) {
    visitor_->OnIncomingNewStream(stream);
  }
  return stream;
}

QuicTransportOWTStreamImpl* QuicTransportOWTClientSession::CreateIncomingStream(
    PendingStream* pending) {
  QuicTransportOWTStreamImpl* stream = new QuicTransportOWTStreamImpl(
      pending, this, BIDIRECTIONAL, task_runner_, event_runner_);
  ActivateStream(absl::WrapUnique(stream));
  if (visitor_) {
    visitor_->OnIncomingNewStream(stream);
  }
  return stream;
}

std::unique_ptr<QuicCryptoClientStreamBase>
QuicTransportOWTClientSession::CreateQuicCryptoStream() {
  return std::make_unique<QuicCryptoClientStream>(
      server_id_, this,
      crypto_config_->proof_verifier()->CreateDefaultContext(), crypto_config_,
      this, /*has_application_state = */ false);
}

void QuicTransportOWTClientSession::OnConfigNegotiated() {
  QuicSession::OnConfigNegotiated();
}

bool QuicTransportOWTClientSession::HasActiveRequestStreams() const {
  return GetNumActiveStreams() + num_draining_streams() > 0;
}

bool QuicTransportOWTClientSession::ShouldKeepConnectionAlive() const {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()) ||
                0u == pending_streams_size());
  return GetNumActiveStreams() + pending_streams_size() > 0;
}

void QuicTransportOWTClientSession::OnStreamClosed(quic::QuicStreamId stream_id) {
  if (visitor_) {
    visitor_->OnStreamClosed(stream_id);
  }
}

void QuicTransportOWTClientSession::OnConnectionClosed(
    const quic::QuicConnectionCloseFrame& frame,
    quic::ConnectionCloseSource source) {
  std::cerr << "QuicTransportOWTClientSession::OnConnectionClosed and client session id:" << connection()->connection_id().ToString() << " in thread" << base::PlatformThread::CurrentId();
  const std::string& session_id_str =
      connection()->client_connection_id().ToString();
  char* id = new char[session_id_str.size() + 1];
  strcpy(id, session_id_str.c_str());
  if (visitor_) {
    visitor_->OnConnectionClosed(id, session_id_str.size());
  }
}

}  // namespace quic
