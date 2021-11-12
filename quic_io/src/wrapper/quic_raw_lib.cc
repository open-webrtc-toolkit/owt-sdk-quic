
#include "net/tools/quic/raw/wrapper/quic_raw_lib.h"

#include <iostream>
#include <string>

#include "base/logging.h"
#include "base/at_exit.h"
#include "base/run_loop.h"
#include "base/task/post_task.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/threading/thread.h"
#include "net/base/net_errors.h"
#include "net/quic/address_utils.h"
#include "net/base/privacy_mode.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/http/transport_security_state.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/third_party/quiche/src/quic/core/quic_error_codes.h"
#include "net/third_party/quiche/src/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/tools/quic/synchronous_host_resolver.h"

#include "base/strings/string_number_conversions.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/crypto/proof_source_chromium.h"

#include "url/gurl.h"

#include "net/tools/quic/raw/quic_raw_stream.h"
#include "net/tools/quic/raw/quic_raw_client.h"
#include "net/tools/quic/raw/quic_raw_server.h"
#include "net/tools/quic/raw/quic_raw_dispatcher.h"
#include "net/tools/quic/raw/quic_raw_server_session.h"

namespace net {

using std::cout;
using std::cerr;
using std::endl;
using std::string;

// FakeProofSource for server
class FakeProofSource : public quic::ProofSource {
 public:
  FakeProofSource() {}
  ~FakeProofSource() override {}

  void GetProof(const quic::QuicSocketAddress& server_address,
                const quic::QuicSocketAddress& client_address,
                const std::string& hostname,
                const std::string& server_config,
                quic::QuicTransportVersion transport_version,
                absl::string_view chlo_hash,
                std::unique_ptr<Callback> callback) override {
    quic::QuicReferenceCountedPointer<ProofSource::Chain> chain =
        GetCertChain(server_address, client_address, hostname);
    quic::QuicCryptoProof proof;
    proof.signature = "fake signature";
    proof.leaf_cert_scts = "fake timestamp";
    callback->Run(true, chain, proof, nullptr);
  }

  quic::QuicReferenceCountedPointer<Chain> GetCertChain(
      const quic::QuicSocketAddress& server_address,
      const ::quic::QuicSocketAddress& client_address,
      const std::string& hostname) override {
    std::vector<std::string> certs;
    certs.push_back("fake cert");
    return quic::QuicReferenceCountedPointer<ProofSource::Chain>(
        new ProofSource::Chain(certs));
  }

  void ComputeTlsSignature(
      const quic::QuicSocketAddress& server_address,
      const ::quic::QuicSocketAddress& client_address,
      const std::string& hostname,
      uint16_t signature_algorithm,
      absl::string_view in,
      std::unique_ptr<SignatureCallback> callback) override {
    callback->Run(true, "fake signature", nullptr);
  }

  ProofSource::TicketCrypter* GetTicketCrypter() override {
    return nullptr;
}
};

// FakeProofVerifier for client
class FakeProofVerifier : public quic::ProofVerifier {
 public:
  quic::QuicAsyncStatus VerifyProof(
      const string& hostname,
      const uint16_t port,
      const string& server_config,
      quic::QuicTransportVersion quic_version,
      absl::string_view  chlo_hash,
      const std::vector<string>& certs,
      const string& cert_sct,
      const string& signature,
      const quic::ProofVerifyContext* context,
      string* error_details,
      std::unique_ptr<quic::ProofVerifyDetails>* details,
      std::unique_ptr<quic::ProofVerifierCallback> callback) override {
    return quic::QUIC_SUCCESS;
  }

  quic::QuicAsyncStatus VerifyCertChain(
      const std::string& hostname,
      const uint16_t port,
      const std::vector<std::string>& certs,
      const std::string& ocsp_response,
      const std::string& cert_sct,
      const quic::ProofVerifyContext* verify_context,
      std::string* error_details,
      std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
      uint8_t* out_alert,
      std::unique_ptr<quic::ProofVerifierCallback> callback) override {
    return quic::QUIC_SUCCESS;
  }

  std::unique_ptr<quic::ProofVerifyContext> CreateDefaultContext() override {
    return nullptr;
  }
};

// RawClient Implementation
class RawClientImpl : public RQuicClientInterface,
                      public quic::QuicRawStream::Visitor {
 public:
  RawClientImpl()
      : stream_{nullptr},
        mtx_{},
        io_thread_(std::make_unique<base::Thread>("quic_lib_clientio_thread")),
        //run_loop_{nullptr},
        client_thread_{std::make_unique<base::Thread>("quic_lib_client_thread")},
        listener_{nullptr},
        next_session_id_{0} {
          printf("RawClientImpl constructor\n");
          base::Thread::Options options;
          options.message_pump_type = base::MessagePumpType::IO;
          io_thread_->StartWithOptions(options);
          client_thread_->StartWithOptions(options);
        }

  ~RawClientImpl() override {
    //stop();
    waitForClose();
  }

  // Implement RQuicClientInterface
  bool start(const char* host, int port) override {
    if (client_thread_) {
      printf("RawClientImpl start\n");
      std::string s_host(host);
      client_thread_->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&RawClientImpl::InitAndRun, base::Unretained(this), s_host, port));
      return true;
    }
    printf("RawClientImpl not start\n");
    return false;
  }

  // Implement RQuicClientInterface
  void stop() override {
    {
      /*std::unique_lock<std::mutex> lck(mtx_);
      if (run_loop_)
        run_loop_->Quit();*/
    }
  }

  // Implement RQuicClientInterface
  void waitForClose() override {
    if (client_thread_) {
      /*client_thread_.join();
      client_thread_.reset();*/
    }
  }

  // Implement RQuicClientInterface
  void send(uint32_t session_id, uint32_t stream_id, const char* data, uint32_t len) override {
    //std::unique_lock<std::mutex> lck(mtx_);
    if (client_thread_) {
      std::string s_data(data, len);
      client_thread_->task_runner()->PostTask(FROM_HERE,
          base::BindOnce(&RawClientImpl::SendOnStream,
              base::Unretained(this), session_id, stream_id, s_data, false));
    }
  }

  // Implement RQuicClientInterface
  void setListener(RQuicListener* listener) override {
    std::cerr << "set client listener" << std::endl;
    listener_ = listener;
  }

  // Implement quic::QuicRawStream::Visitor
  void OnClose(quic::QuicRawStream* stream) override {
    if (stream == stream_) {
      stream_ = nullptr;
    }
  }
  void OnData(quic::QuicRawStream* stream, char* data, size_t len) override {
    if (client_thread_) {
      client_thread_->task_runner()->PostTask(FROM_HERE,
          base::BindOnce(&RawClientImpl::ProcessData,
              base::Unretained(this), stream->id(), data, len));
    }
  }
 private:
  std::unique_ptr<quic::ProofVerifier> CreateProofVerifier() {
    std::unique_ptr<quic::ProofVerifier> proof_verifier;
    bool disable_cert = true;
    if (disable_cert) {
      proof_verifier.reset(new FakeProofVerifier());
    }/* else {
      // For secure QUIC we need to verify the cert chain.
      std::unique_ptr<net::CertVerifier> cert_verifier(net::CertVerifier::CreateDefault());
      std::unique_ptr<net::TransportSecurityState> transport_security_state(
          new net::TransportSecurityState);
      std::unique_ptr<net::MultiLogCTVerifier> ct_verifier(new net::MultiLogCTVerifier());
      std::unique_ptr<net::CTPolicyEnforcer> ct_policy_enforcer(
          new net::DefaultCTPolicyEnforcer());
      proof_verifier.reset(new net::ProofVerifierChromium(
          cert_verifier.get(), ct_policy_enforcer.get(),
          transport_security_state.get(), ct_verifier.get()));
    }*/
    return proof_verifier;
  }

  void InitAndRun(std::string host, int port) {
    //base::RunLoop run_loop;

    // Determine IP address to connect to from supplied hostname.
    quic::QuicIpAddress ip_addr;

    GURL url("https://www.example.org");
    
    if (!ip_addr.FromString(host)) {
      net::AddressList addresses;
      int rv = net::SynchronousHostResolver::Resolve(host, &addresses);
      if (rv != net::OK) {
        LOG(ERROR) << "Unable to resolve '" << host
                   << "' : " << net::ErrorToShortString(rv);
        std::cerr << "Unable to resolve '" << host
                   << "' : " << net::ErrorToShortString(rv);
        return;
      }
      ip_addr =
          net::ToQuicIpAddress(addresses[0].address());
    }

    quic::QuicServerId server_id(url.host(), url.EffectiveIntPort(),
                                 net::PRIVACY_MODE_DISABLED);
    quic::ParsedQuicVersionVector versions = quic::CurrentSupportedVersions();

    client_ = std::make_unique<net::QuicRawClient>(quic::QuicSocketAddress(ip_addr, port),
                                server_id, versions, CreateProofVerifier());

    client_->set_initial_max_packet_length(quic::kDefaultMaxPacketSize);
    if (!client_->Initialize()) {
      std::cerr << "Failed to initialize client." << std::endl;
      return;
    }
    if (!client_->Connect()) {
      std::cerr << "Failed to connect." << std::endl;
      return;
    }

    std::cerr << "client connect to quic server succeed" << std::endl;
    quic::QuicRawClientSession* session_ = client_->client_session();
    std::cerr << "client CreateOutgoingBidirectionalStream" << std::endl;
    stream_ = session_->CreateOutgoingBidirectionalStream();
    std::cerr << "client set stream visitor" << std::endl;
    stream_->set_visitor(this);
    std::cerr << "client store session info" << std::endl;
    session_ptrs_[next_session_id_] = session_;
    if (listener_) {
      uint32_t stream_id = stream_->id();
      std::cerr << "session id is ready:" << next_session_id_ << " stream:" << stream_id << std::endl;
      listener_->onReady(next_session_id_, stream_id);
    }
    next_session_id_++;
/*
  {
    std::unique_lock<std::mutex> lck(mtx_);
    run_loop_ = &run_loop;
  }
  
  // cout << "get port:" << client.SocketPort() << endl;
  run_loop_->Run();
  {
    std::unique_lock<std::mutex> lck(mtx_);
    run_loop_ = nullptr;
  }
  */
  }

  void SendOnStream(uint32_t session_id, uint32_t stream_id, const std::string& data, bool fin) {
    std::cerr << "SendOnStream data:" << data;
    if (session_ptrs_.count(session_id) > 0) {
      quic::QuicStream* stream =
          session_ptrs_[session_id]->GetOrCreateStream(stream_id);
      if (stream) {
        std::cerr << "WriteOrBufferData";
        stream->WriteOrBufferData(data, fin, nullptr);
      } else {
        cerr << "Failed to get stream: " << stream_id << endl;
      }
    }
    std::cerr << "Finish SendOnStream data" << endl;
  }

  void ProcessData(uint32_t stream_id, char* data, size_t len) {

    if (listener_) {
      // Use 0 for client session
      listener_->onData(0, stream_id, data, len);
    }
  }
  quic::QuicRawStream* stream_;
  std::mutex mtx_;
  std::unique_ptr<base::Thread> io_thread_;
  //base::RunLoop* run_loop_;
  std::unique_ptr<base::Thread> client_thread_;
  RQuicListener* listener_;
  uint32_t next_session_id_;
  std::unordered_map<uint32_t, quic::QuicRawClientSession*> session_ptrs_;
  std::unique_ptr<net::QuicRawClient> client_;
};


// RawServer Implementation
class RawServerImpl : public RQuicServerInterface,
                      public quic::QuicRawDispatcher::Visitor,
                      public quic::QuicRawServerSession::Visitor,
                      public quic::QuicRawStream::Visitor {
 public:
  RawServerImpl(std::string cert_file, std::string key_file)
      : cert_file_{cert_file},
        key_file_{key_file},
        mtx_{},
        //run_loop_{nullptr},
        io_thread_(std::make_unique<base::Thread>("quic_lib_serverio_thread")),
        server_thread_{std::make_unique<base::Thread>("quic_lib_server_thread")},
        listener_{nullptr},
        server_port_{0},
        stream_{nullptr},
        next_session_id_{0} {
          base::Thread::Options options;
          options.message_pump_type = base::MessagePumpType::IO;
          io_thread_->StartWithOptions(options);
          server_thread_->StartWithOptions(options);
        }

  ~RawServerImpl() override {
    //stop();
    waitForClose();
  }

  // Implement RQuicServerInterface
  bool listen(int port) override {
    printf("Server listen at port:%d\n", port);
    if (server_thread_) {
      server_thread_->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&RawServerImpl::InitAndRun, base::Unretained(this), port));
      return true;
    }
    return false;
  }

  // Implement RQuicServerInterface
  void stop() override {
    {
      /*std::unique_lock<std::mutex> lck(mtx_);
      if (run_loop_)
        run_loop_->Quit();*/
    }
  }

  // Implement RQuicServerInterface
  void waitForClose() override {
    if (server_thread_) {
      /*server_thread_.join();
      server_thread_.reset();*/
    }
  }

  // Implement RQuicServerInterface
  int getServerPort() override {
    return server_port_;
  }


  // Implement RQuicServerInterface
  void send(uint32_t session_id,
            uint32_t stream_id,
            const char* data,
            uint32_t len) override {
    std::unique_lock<std::mutex> lck(mtx_);
    if (server_thread_) {
      std::string s_data(data, len);
      server_thread_->task_runner()->PostTask(FROM_HERE,
          base::BindOnce(&RawServerImpl::SendOnSession,
              base::Unretained(this), session_id, stream_id, s_data, false));
    }
  }

  // Implement RQuicServerInterface
  void setListener(RQuicListener* listener) override {
    listener_ = listener;
  }

  // Implement quic::QuicRawDispatcher::Visitor
  void OnSessionCreated(quic::QuicRawServerSession* session) override {
    printf("Server new session created:%d\n", next_session_id_);
    session_ids_[session] = next_session_id_;
    session_ptrs_[next_session_id_] = session;
    next_session_id_++;
    session->set_visitor(this);
  }
  void OnSessionClosed(quic::QuicRawServerSession* session) override {
    if (session_ids_.count(session) > 0) {
      uint32_t session_id = session_ids_[session];
      session_ids_.erase(session);
      session_ptrs_.erase(session_id);
    }
  }

  // Implement quic::QuicRawServerSession::Visitor
  void OnIncomingStream(quic::QuicRawServerSession* session,
                        quic::QuicRawStream* stream) override {
    printf("Server get incoming stream:\n");
    if (session_ids_.count(session) > 0) {
      uint32_t session_id = session_ids_[session];
      stream_sessions_[stream] = session_id;
    } else {
      cerr << "No mapping sessions for incoming stream" << endl;
    }
    stream->set_visitor(this);
    if (!stream_) {
      stream_ = stream;
    }
  }

  // Implement quic::QuicRawStream::Visitor
  void OnClose(quic::QuicRawStream* stream) override {
    if (stream_sessions_.count(stream)) {
      stream_sessions_.erase(stream);
    } else {
      cerr << "No mapping session for closing stream" << endl;
    }
    if (stream == stream_) {
      stream_ = nullptr;
    }
  }
  void OnData(quic::QuicRawStream* stream, char* data, size_t len) override {
    if (io_thread_) {
      uint32_t session_id = stream_sessions_[stream];
      io_thread_->task_runner()->PostTask(FROM_HERE,
          base::BindOnce(&RawServerImpl::ProcessData,
              base::Unretained(this), session_id, stream->id(), data, len));
    }
  }

 private:
  std::unique_ptr<quic::ProofSource> CreateProofSource() {
    bool disable_cert = false;
    if (disable_cert) {
      std::unique_ptr<FakeProofSource> proof_source(
          new FakeProofSource());
      return proof_source;
    } else {
      std::unique_ptr<net::ProofSourceChromium> proof_source(
          new net::ProofSourceChromium());
      CHECK(proof_source->Initialize(
          base::FilePath(cert_file_),
          base::FilePath(key_file_), base::FilePath()));
      return proof_source;
    }
  }

  void InitAndRun(int port) {
    //base::RunLoop run_loop;

    // Determine IP address to connect to from supplied hostname.
    net::IPAddress ip = net::IPAddress::IPv6AllZeros();

    quic::QuicConfig config;
    server_ = std::make_unique<net::QuicRawServer>(
        CreateProofSource(),
        config, quic::QuicCryptoServerConfig::ConfigOptions(),
        quic::AllSupportedVersions());

    int rc = server_->Listen(net::IPEndPoint(ip, port));
    if (rc < 0) {
      return;
    }

    server_->dispatcher()->set_visitor(this);
    server_port_ = server_->server_address().port();

    /*{
      std::unique_lock<std::mutex> lck(mtx_);
      run_loop_ = &run_loop;
    }

    run_loop_->Run();
    {
      std::unique_lock<std::mutex> lck(mtx_);
      run_loop_ = nullptr;
    }*/
  }

  void SendOnSession(uint32_t session_id, uint32_t stream_id,
                     const std::string& data, bool fin) {
    std::cerr << "SendOnSession data:" << data;
    if (session_ptrs_.count(session_id) > 0) {
      quic::QuicStream* stream =
          session_ptrs_[session_id]->GetOrCreateStream(stream_id);
      if (stream) {
        stream->WriteOrBufferData(data, fin, nullptr);
      } else {
        cerr << "Failed to get stream: " << stream_id << endl;
      }
    }
  }

  void ProcessData(uint32_t session_id, uint32_t stream_id, char* data, size_t len) {

    if (listener_) {
      listener_->onData(session_id, stream_id, data, len);
    }
  }

  std::string cert_file_;
  std::string key_file_;
  std::mutex mtx_;
  //base::RunLoop* run_loop_;
  std::unique_ptr<base::Thread> io_thread_;
  std::unique_ptr<base::Thread> event_thread_;
  std::unique_ptr<base::Thread> server_thread_;
  RQuicListener* listener_;
  int server_port_;
  quic::QuicRawStream* stream_;
  uint32_t next_session_id_;
  std::unordered_map<quic::QuicRawServerSession*, uint32_t> session_ids_;
  std::unordered_map<uint32_t, quic::QuicRawServerSession*> session_ptrs_;
  std::unordered_map<quic::QuicRawStream*, uint32_t> stream_sessions_;
  std::unique_ptr<net::QuicRawServer> server_;
};

bool raw_factory_intialized = false;
std::shared_ptr<base::AtExitManager> exit_manager;

void initialize() {
  if (!raw_factory_intialized) {
    base::ThreadPoolInstance::CreateAndStartWithDefaultParams("raw_quic_factory");
    exit_manager.reset(new base::AtExitManager());
    raw_factory_intialized = true;
    printf("Set min log level to info\n");
    logging::LoggingSettings settings;
    settings.logging_dest = logging::LOG_TO_STDERR;
    logging::InitLogging(settings);
    logging::SetMinLogLevel(-3);
  }
}

RQuicClientInterface* RQuicFactory::createQuicClient() {
  printf("RQuicFactory::createQuicClient in thread:%d\n", base::PlatformThread::CurrentId());
  initialize();
  RQuicClientInterface* client = new RawClientImpl();
  return client;
}

RQuicServerInterface* RQuicFactory::createQuicServer(const char* cert_file, const char* key_file) {
  printf("RQuicFactory::createQuicServer\n");
  initialize();
  RQuicServerInterface* server = new RawServerImpl(cert_file, key_file);
  return server;
}

} //namespace net
