
#include "owt/quic_transport/sdk/impl/quic_transport_owt_client_session.h"

#include <string>

#include "net/third_party/quiche/src/quiche/quic/core/crypto/crypto_protocol.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_flag_utils.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_logging.h"

namespace quic {

QuicTransportOwtClientSession::QuicTransportOwtClientSession(
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

QuicTransportOwtClientSession::~QuicTransportOwtClientSession() = default;

void QuicTransportOwtClientSession::Initialize() {
  crypto_stream_ = CreateQuicCryptoStream();
  QuicSession::Initialize();
}

void QuicTransportOwtClientSession::OnProofValid(
    const QuicCryptoClientConfig::CachedState& /*cached*/) {}

void QuicTransportOwtClientSession::OnProofVerifyDetailsAvailable(
    const ProofVerifyDetails& /*verify_details*/) {}

bool QuicTransportOwtClientSession::ShouldCreateOutgoingBidirectionalStream() {
  if (!crypto_stream_->encryption_established()) {
    LOG(ERROR) << "Encryption not active so no outgoing stream created.";
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

bool QuicTransportOwtClientSession::ShouldCreateOutgoingUnidirectionalStream() {
  QUIC_BUG(quic_bug_10396_1) << "Try to create outgoing unidirectional client data streams";
  return false;
}

owt::quic::QuicTransportStreamInterface*
QuicTransportOwtClientSession::CreateOutgoingBidirectionalStream() {
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
QuicTransportOwtClientSession::CreateOutgoingUnidirectionalStream() {
  QUIC_BUG(quic_bug_10396_2) << "Try to create outgoing unidirectional client data streams";
  return nullptr;
}

QuicCryptoClientStreamBase* QuicTransportOwtClientSession::GetMutableCryptoStream() {
  return crypto_stream_.get();
}

const QuicCryptoClientStreamBase* QuicTransportOwtClientSession::GetCryptoStream()
    const {
  return crypto_stream_.get();
}

void QuicTransportOwtClientSession::CryptoConnect() {
  DCHECK(flow_controller());
  crypto_stream_->CryptoConnect();
}

int QuicTransportOwtClientSession::GetNumSentClientHellos() const {
  return crypto_stream_->num_sent_client_hellos();
}

int QuicTransportOwtClientSession::GetNumReceivedServerConfigUpdates() const {
  return crypto_stream_->num_scup_messages_received();
}

bool QuicTransportOwtClientSession::EarlyDataAccepted() const {
  return crypto_stream_->EarlyDataAccepted();
}

bool QuicTransportOwtClientSession::ReceivedInchoateReject() const {
  return crypto_stream_->ReceivedInchoateReject();
}

bool QuicTransportOwtClientSession::ShouldCreateIncomingStream(QuicStreamId id) {
  if (!connection()->connected()) {
    QUIC_BUG(quic_bug_10396_3) << "ShouldCreateIncomingStream called when disconnected";
    return false;
  }
  if (transport_goaway_received() && respect_goaway_) {
    LOG(INFO) << "Failed to create a new outgoing stream. "
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

QuicTransportOwtStreamImpl* QuicTransportOwtClientSession::CreateIncomingStream(QuicStreamId id) {
  if (!ShouldCreateIncomingStream(id)) {
    return nullptr;
  }

  QuicTransportOwtStreamImpl* stream = new QuicTransportOwtStreamImpl(
      id, this, BIDIRECTIONAL, task_runner_, event_runner_);
  ActivateStream(absl::WrapUnique(stream));
  if (visitor_) {
    visitor_->OnIncomingNewStream(stream);
  }
  return stream;
}

QuicTransportOwtStreamImpl* QuicTransportOwtClientSession::CreateIncomingStream(
    PendingStream* pending) {
  QuicTransportOwtStreamImpl* stream = new QuicTransportOwtStreamImpl(
      pending, this, BIDIRECTIONAL, task_runner_, event_runner_);
  ActivateStream(absl::WrapUnique(stream));
  if (visitor_) {
    visitor_->OnIncomingNewStream(stream);
  }
  return stream;
}

std::unique_ptr<QuicCryptoClientStreamBase>
QuicTransportOwtClientSession::CreateQuicCryptoStream() {
  return std::make_unique<QuicCryptoClientStream>(
      server_id_, this,
      crypto_config_->proof_verifier()->CreateDefaultContext(), crypto_config_,
      this, /*has_application_state = */ false);
}

void QuicTransportOwtClientSession::OnConfigNegotiated() {
  QuicSession::OnConfigNegotiated();
}

bool QuicTransportOwtClientSession::HasActiveRequestStreams() const {
  return GetNumActiveStreams() + num_draining_streams() > 0;
}

bool QuicTransportOwtClientSession::ShouldKeepConnectionAlive() const {
  return true;
}

void QuicTransportOwtClientSession::OnStreamClosed(quic::QuicStreamId stream_id) {
  if (visitor_) {
    visitor_->OnStreamClosed(stream_id);
  }
}

void QuicTransportOwtClientSession::OnConnectionClosed(
    const quic::QuicConnectionCloseFrame& frame,
    quic::ConnectionCloseSource source) {
  const std::string& session_id_str =
      connection()->client_connection_id().ToString();
  char* id = new char[session_id_str.size() + 1];
  strcpy(id, session_id_str.c_str());
  if (visitor_) {
    visitor_->OnConnectionClosed(id, session_id_str.size());
  }
}

}  // namespace quic
