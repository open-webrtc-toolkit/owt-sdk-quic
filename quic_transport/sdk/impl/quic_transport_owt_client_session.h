// A client specific QuicSession subclass.

#ifndef QUIC_TRANSPORT_OWT_CLIENT_SESSION_H_
#define QUIC_TRANSPORT_OWT_CLIENT_SESSION_H_

#include <memory>
#include <string>

#include "net/third_party/quiche/src/quic/core/quic_crypto_client_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_packets.h"

#include "owt/quic_transport/sdk/impl/quic_transport_owt_stream_impl.h"
#include "base/single_thread_task_runner.h"

namespace quic {

class QuicConnection;
class QuicServerId;

class QuicTransportOWTClientSession
    : public QuicSession,
      public QuicCryptoClientStream::ProofHandler {
 public:
  // Visitor receives callbacks from the QuicRawServerSession.
  class QUIC_EXPORT_PRIVATE Visitor {
   public:
    Visitor() {}
    Visitor(const Visitor&) = delete;
    Visitor& operator=(const Visitor&) = delete;

    // Called when new incoming stream created
    virtual void OnIncomingNewStream(QuicTransportOWTStreamImpl* stream) = 0;

   protected:
    virtual ~Visitor() {}
  };

  // Takes ownership of |connection|. Caller retains ownership of
  // |promised_by_url|.
  QuicTransportOWTClientSession(QuicConnection* connection,
                        QuicSession::Visitor* visitor,
                        const QuicConfig& config,
                        const ParsedQuicVersionVector& supported_versions,
                        const QuicServerId& server_id,
                        QuicCryptoClientConfig* crypto_config,
                        base::SingleThreadTaskRunner* io_runner,
                        base::SingleThreadTaskRunner* event_runner);
  QuicTransportOWTClientSession(const QuicTransportOWTClientSession&) = delete;
  QuicTransportOWTClientSession& operator=(const QuicTransportOWTClientSession&) = delete;
  ~QuicTransportOWTClientSession() override;
  // Set up the QuicRawClientSession. Must be called prior to use.
  void Initialize() override;


  void OnConfigNegotiated() override;

  // QuicSession methods:
  QuicTransportStreamInterface* CreateOutgoingBidirectionalStream();
  QuicTransportStreamInterface* CreateOutgoingUnidirectionalStream();
  QuicCryptoClientStreamBase* GetMutableCryptoStream() override;
  const QuicCryptoClientStreamBase* GetCryptoStream() const override;

  // QuicCryptoClientStream::ProofHandler methods:
  void OnProofValid(const QuicCryptoClientConfig::CachedState& cached) override;
  void OnProofVerifyDetailsAvailable(
      const ProofVerifyDetails& verify_details) override;

  // Performs a crypto handshake with the server.
  virtual void CryptoConnect();

  // Returns the number of client hello messages that have been sent on the
  // crypto stream. If the handshake has completed then this is one greater
  // than the number of round-trips needed for the handshake.
  int GetNumSentClientHellos() const;

  int GetNumReceivedServerConfigUpdates() const;

  // Returns true if early data (0-RTT data) was sent and the server accepted
  // it.
  bool EarlyDataAccepted() const;

  // Returns true if the handshake was delayed one round trip by the server
  // because the server wanted proof the client controls its source address
  // before progressing further. In Google QUIC, this would be due to an
  // inchoate REJ in the QUIC Crypto handshake; in IETF QUIC this would be due
  // to a Retry packet.
  // TODO(nharper): Consider a better name for this method.
  bool ReceivedInchoateReject() const;

  // Returns true if the session has active request streams.
  bool HasActiveRequestStreams() const;

  void set_respect_goaway(bool respect_goaway) {
    respect_goaway_ = respect_goaway;
  }

  bool IsConnected() { return connection()->connected(); }
  void set_visitor(Visitor* visitor) { visitor_ = visitor; }

 protected:
  // QuicSession methods:
  QuicTransportOWTStreamImpl* CreateIncomingStream(QuicStreamId id) override;
  // QuicRawStream* CreateIncomingStream(PendingStream pending) override;
  // If an outgoing stream can be created, return true.
  QuicTransportOWTStreamImpl* CreateIncomingStream(PendingStream* pending) override;
  bool ShouldCreateOutgoingBidirectionalStream();
  bool ShouldCreateOutgoingUnidirectionalStream();

  // Returns true if there are open HTTP requests.
  bool ShouldKeepConnectionAlive() const override;

  // // If an incoming stream can be created, return true.
  // // TODO(fayang): move this up to QuicSpdyClientSessionBase.
  bool ShouldCreateIncomingStream(QuicStreamId id);

  // Create the crypto stream. Called by Initialize().
  virtual std::unique_ptr<QuicCryptoClientStreamBase> CreateQuicCryptoStream();

  const QuicServerId& server_id() { return server_id_; }
  QuicCryptoClientConfig* crypto_config() { return crypto_config_; }

 private:
  std::unique_ptr<QuicCryptoClientStreamBase> crypto_stream_;
  QuicServerId server_id_;
  QuicCryptoClientConfig* crypto_config_;

  base::SingleThreadTaskRunner* task_runner_;
  base::SingleThreadTaskRunner* event_runner_;

  // If this is set to false, the client will ignore server GOAWAYs and allow
  // the creation of streams regardless of the high chance they will fail.
  bool respect_goaway_;
  Visitor* visitor_;
};

}  // namespace quic

#endif  // QUIC_TRANSPORT_OWT_CLIENT_SESSION_H_
