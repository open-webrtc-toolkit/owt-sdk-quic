// A client specific QuicSession subclass.

#ifndef NET_TOOLS_QUIC_RAW_QUIC_RAW_CLIENT_SESSION_H_
#define NET_TOOLS_QUIC_RAW_QUIC_RAW_CLIENT_SESSION_H_

#include <memory>
#include <string>

#include "net/third_party/quiche/src/quic/core/quic_crypto_client_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_packets.h"

#include "net/tools/quic/raw/quic_raw_stream.h"


namespace quic {

class QuicConnection;
class QuicServerId;

class QuicRawClientSession
    : public QuicSession,
      public QuicCryptoClientStream::ProofHandler {
 public:
  // Takes ownership of |connection|. Caller retains ownership of
  // |promised_by_url|.
  QuicRawClientSession(QuicConnection* connection,
                        QuicSession::Visitor* visitor,
                        const QuicConfig& config,
                        const ParsedQuicVersionVector& supported_versions,
                        const QuicServerId& server_id,
                        QuicCryptoClientConfig* crypto_config);
  QuicRawClientSession(const QuicRawClientSession&) = delete;
  QuicRawClientSession& operator=(const QuicRawClientSession&) = delete;
  ~QuicRawClientSession() override;
  // Set up the QuicRawClientSession. Must be called prior to use.
  void Initialize() override;


  void OnConfigNegotiated() override;

  // QuicSession methods:
  QuicRawStream* CreateOutgoingBidirectionalStream();
  QuicRawStream* CreateOutgoingUnidirectionalStream();
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

 protected:
  // QuicSession methods:
  QuicRawStream* CreateIncomingStream(QuicStreamId id) override;
  // QuicRawStream* CreateIncomingStream(PendingStream pending) override;
  // If an outgoing stream can be created, return true.
  QuicRawStream* CreateIncomingStream(PendingStream* pending) override;
  bool ShouldCreateOutgoingBidirectionalStream();
  bool ShouldCreateOutgoingUnidirectionalStream();

  // Returns true if there are open HTTP requests.
  bool ShouldKeepConnectionAlive() const override;

  // // If an incoming stream can be created, return true.
  // // TODO(fayang): move this up to QuicSpdyClientSessionBase.
  bool ShouldCreateIncomingStream(QuicStreamId id);

  // Create the crypto stream. Called by Initialize().
  virtual std::unique_ptr<QuicCryptoClientStreamBase> CreateQuicCryptoStream();

  // Unlike CreateOutgoingBidirectionalStream, which applies a bunch of
  // sanity checks, this simply returns a new QuicSpdyClientStream. This may be
  // used by subclasses which want to use a subclass of QuicSpdyClientStream for
  // streams but wish to use the sanity checks in
  // CreateOutgoingBidirectionalStream.
  virtual std::unique_ptr<QuicRawStream> CreateClientStream();

  const QuicServerId& server_id() { return server_id_; }
  QuicCryptoClientConfig* crypto_config() { return crypto_config_; }

 private:
  std::unique_ptr<QuicCryptoClientStreamBase> crypto_stream_;
  QuicServerId server_id_;
  QuicCryptoClientConfig* crypto_config_;

  // If this is set to false, the client will ignore server GOAWAYs and allow
  // the creation of streams regardless of the high chance they will fail.
  bool respect_goaway_;
};

}  // namespace quic

#endif  // NET_TOOLS_QUIC_RAW_QUIC_RAW_CLIENT_SESSION_H_
