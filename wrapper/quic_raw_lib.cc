
#include "net/tools/quic/raw/wrapper/quic_raw_lib.h"

#include <iostream>
#include <thread>
#include <string>

#include "base/at_exit.h"
#include "base/run_loop.h"
#include "base/message_loop/message_loop.h"
#include "base/task/post_task.h"
#include "base/task/task_scheduler/task_scheduler.h"
#include "net/base/net_errors.h"
#include "net/base/privacy_mode.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/http/transport_security_state.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/third_party/quic/core/quic_error_codes.h"
#include "net/third_party/quic/core/quic_packets.h"
#include "net/third_party/quic/core/quic_server_id.h"
#include "net/third_party/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quic/platform/api/quic_str_cat.h"
#include "net/third_party/quic/platform/api/quic_string_piece.h"
#include "net/third_party/quic/platform/api/quic_text_utils.h"
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

using net::CertVerifier;
using net::CTVerifier;
using net::MultiLogCTVerifier;
using quic::ProofVerifier;
using net::ProofVerifierChromium;
using quic::QuicStringPiece;
using net::TransportSecurityState;
using std::cout;
using std::cerr;
using std::endl;
using std::string;

// FakeProofVerifier for client
class FakeProofVerifier : public quic::ProofVerifier {
 public:
  quic::QuicAsyncStatus VerifyProof(
      const string& hostname,
      const uint16_t port,
      const string& server_config,
      quic::QuicTransportVersion quic_version,
      quic::QuicStringPiece chlo_hash,
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
      const std::vector<std::string>& certs,
      const quic::ProofVerifyContext* verify_context,
      std::string* error_details,
      std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
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
        message_loop_{nullptr},
        run_loop_{nullptr},
        client_thread_{nullptr},
        listener_{nullptr} {}

  ~RawClientImpl() override {
    stop();
    waitForClose();
  }

  // Implement RQuicClientInterface
  bool start(const char* host, int port) override {
    if (!client_thread_) {
      std::string s_host(host);
      client_thread_.reset(
          new std::thread(&RawClientImpl::InitAndRun, this, s_host, port));
      return true;
    }
    return false;
  }

  // Implement RQuicClientInterface
  void stop() override {
    {
      std::unique_lock<std::mutex> lck(mtx_);
      if (message_loop_) {
        message_loop_->task_runner()->PostTask(FROM_HERE, run_loop_->QuitClosure());
      }
    }
  }

  // Implement RQuicClientInterface
  void waitForClose() override {
    if (client_thread_) {
      client_thread_->join();
    }
  }

  // Implement RQuicClientInterface
  void send(const char* data, uint32_t len) override {
    std::unique_lock<std::mutex> lck(mtx_);
    if (message_loop_) {
      std::string s_data(data, len);
      message_loop_->task_runner()->PostTask(FROM_HERE,
          base::BindOnce(&RawClientImpl::SendOnStream, base::Unretained(this), s_data, false));
    }
  }

  // Implement RQuicClientInterface
  void setListener(RQuicListener* listener) override {
    listener_ = listener;
  }

  // Implement quic::QuicRawStream::Visitor
  void OnClose(quic::QuicRawStream* stream) override {};
  void OnData(quic::QuicRawStream* stream, char* data, size_t len) override {
    if (listener_) {
      listener_->onData(stream->id(), data, len);
    }
  }
 private:
  void InitAndRun(std::string host, int port) {
    base::MessageLoopForIO message_loop;
    base::RunLoop run_loop;

    // Determine IP address to connect to from supplied hostname.
    quic::QuicIpAddress ip_addr;

    GURL url("https://www.example.org");
    
    if (!ip_addr.FromString(host)) {
      net::AddressList addresses;
      int rv = net::SynchronousHostResolver::Resolve(host, &addresses);
      if (rv != net::OK) {
        LOG(ERROR) << "Unable to resolve '" << host
                   << "' : " << net::ErrorToShortString(rv);
        return;
      }
      ip_addr =
          quic::QuicIpAddress(quic::QuicIpAddressImpl(addresses[0].address()));
    }

    quic::QuicServerId server_id(url.host(), url.EffectiveIntPort(),
                                 net::PRIVACY_MODE_DISABLED);
    quic::ParsedQuicVersionVector versions = quic::CurrentSupportedVersions();

    // For secure QUIC we need to verify the cert chain.
    std::unique_ptr<CertVerifier> cert_verifier(CertVerifier::CreateDefault());
    std::unique_ptr<TransportSecurityState> transport_security_state(
        new TransportSecurityState);
    std::unique_ptr<MultiLogCTVerifier> ct_verifier(new MultiLogCTVerifier());
    std::unique_ptr<net::CTPolicyEnforcer> ct_policy_enforcer(
        new net::DefaultCTPolicyEnforcer());
    std::unique_ptr<quic::ProofVerifier> proof_verifier;

    bool disable_cert = true;
    if (disable_cert) {
      proof_verifier.reset(new FakeProofVerifier());
    } else {
      proof_verifier.reset(new ProofVerifierChromium(
          cert_verifier.get(), ct_policy_enforcer.get(),
          transport_security_state.get(), ct_verifier.get()));
    }

    net::QuicRawClient client(quic::QuicSocketAddress(ip_addr, port),
                                server_id, versions, std::move(proof_verifier));

    client.set_initial_max_packet_length(quic::kDefaultMaxPacketSize);
    if (!client.Initialize()) {
      std::cerr << "Failed to initialize client." << std::endl;
      return;
    }
    if (!client.Connect()) {
      std::cerr << "Failed to connect." << std::endl;
      return;
    }

    stream_ = client.client_session()->CreateOutgoingBidirectionalStream();
    stream_->set_visitor(this);

    {
      std::unique_lock<std::mutex> lck(mtx_);
      message_loop_ = &message_loop;
      run_loop_ = &run_loop;
    }
    if (listener_) {
      listener_->onReady();
    }
    // cout << "get port:" << client.SocketPort() << endl;
    run_loop_->Run();
    {
      std::unique_lock<std::mutex> lck(mtx_);
      message_loop_ = nullptr;
      run_loop_ = nullptr;
    }
  }

  void SendOnStream(const std::string& data, bool fin) {
    if (stream_) {
      stream_->WriteOrBufferData(data, fin, nullptr);
    }
  }
  quic::QuicRawStream* stream_;
  std::mutex mtx_;
  base::MessageLoopForIO* message_loop_;
  base::RunLoop* run_loop_;
  std::unique_ptr<std::thread> client_thread_;
  RQuicListener* listener_;
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
        message_loop_{nullptr},
        run_loop_{nullptr},
        server_thread_{nullptr},
        listener_{nullptr},
        server_port_{0},
        stream_{nullptr} {}

  ~RawServerImpl() override {
    stop();
    waitForClose();
  }

  // Implement RQuicServerInterface
  bool listen(int port) override {
    if (!server_thread_) {
      server_thread_.reset(
          new std::thread(&RawServerImpl::InitAndRun, this, port));
      return true;
    }
    return false;
  }

  // Implement RQuicServerInterface
  void stop() override {
    {
      std::unique_lock<std::mutex> lck(mtx_);
      if (message_loop_) {
        message_loop_->task_runner()->PostTask(FROM_HERE, run_loop_->QuitClosure());
      }
    }
  }

  // Implement RQuicServerInterface
  void waitForClose() override {
    if (server_thread_) {
      server_thread_->join();
    }
  }

  // Implement RQuicServerInterface
  int getServerPort() override {
    return server_port_;
  }

  // Implement RQuicServerInterface
  void send(const char* data, uint32_t len) override {
    std::unique_lock<std::mutex> lck(mtx_);
    if (message_loop_) {
      message_loop_->task_runner()->PostTask(FROM_HERE, run_loop_->QuitClosure());
    }
    if (message_loop_) {
      std::string s_data(data);
      message_loop_->task_runner()->PostTask(FROM_HERE,
          base::BindOnce(&RawServerImpl::SendOnStream, base::Unretained(this), s_data, false));
    }
  }

  // Implement RQuicServerInterface
  void setListener(RQuicListener* listener) override {
    listener_ = listener;
  }

  // Implement quic::QuicRawDispatcher::Visitor
  void OnSessionCreated(quic::QuicRawServerSession* session) override {
    session->set_visitor(this);
  }

  // Implement quic::QuicRawServerSession::Visitor
  void OnIncomingStream(quic::QuicRawStream* stream) override {
    stream->set_visitor(this);
    if (!stream_) {
      // cout << "incoming stream:" << stream->id() << endl;
      stream_ = stream;
    }
  }

  // Implement quic::QuicRawStream::Visitor
  void OnClose(quic::QuicRawStream* stream) override {};
  void OnData(quic::QuicRawStream* stream, char* data, size_t len) override {
    if (listener_) {
      listener_->onData(stream->id(), data, len);
    }
  }

 private:
  std::unique_ptr<quic::ProofSource> CreateProofSource(
    const base::FilePath& cert_path,
    const base::FilePath& key_path) {
    std::unique_ptr<net::ProofSourceChromium> proof_source(
        new net::ProofSourceChromium());
    CHECK(proof_source->Initialize(cert_path, key_path, base::FilePath()));
    return std::move(proof_source);
  }

  void InitAndRun(int port) {
    base::MessageLoopForIO message_loop;
    base::RunLoop run_loop;

    // Determine IP address to connect to from supplied hostname.
    net::IPAddress ip = net::IPAddress::IPv6AllZeros();

    quic::QuicConfig config;
    net::QuicRawServer server(
        CreateProofSource(base::FilePath(cert_file_), base::FilePath(key_file_)),
        config, quic::QuicCryptoServerConfig::ConfigOptions(),
        quic::AllSupportedVersions());

    int rc = server.Listen(net::IPEndPoint(ip, port));
    if (rc < 0) {
      return;
    }

    server.dispatcher()->set_visitor(this);
    server_port_ = server.server_address().port();

    {
      std::unique_lock<std::mutex> lck(mtx_);
      message_loop_ = &message_loop;
      run_loop_ = &run_loop;
    }
    if (listener_) {
      listener_->onReady();
    }
    run_loop_->Run();
    {
      std::unique_lock<std::mutex> lck(mtx_);
      message_loop_ = nullptr;
      run_loop_ = nullptr;
    }
  }

  void SendOnStream(const std::string& data, bool fin) {
    if (stream_) {
      stream_->WriteOrBufferData(data, fin, nullptr);
    }
  }

  std::string cert_file_;
  std::string key_file_;
  std::mutex mtx_;
  base::MessageLoopForIO* message_loop_;
  base::RunLoop* run_loop_;
  std::unique_ptr<std::thread> server_thread_;
  RQuicListener* listener_;
  int server_port_;
  quic::QuicRawStream* stream_;
};

bool raw_factory_intialized = false;
std::shared_ptr<base::AtExitManager> exit_manager;

void initialize() {
  if (!raw_factory_intialized) {
    base::TaskScheduler::CreateAndStartWithDefaultParams("raw_quic_factory");
    exit_manager.reset(new base::AtExitManager());
    raw_factory_intialized = true;
  }
}

RQuicClientInterface* RQuicFactory::createQuicClient() {
  initialize();
  RQuicClientInterface* client = new RawClientImpl();
  return client;
}

RQuicServerInterface* RQuicFactory::createQuicServer(const char* cert_file, const char* key_file) {
  initialize();
  RQuicServerInterface* server = new RawServerImpl(cert_file, key_file);
  return server;
}

} //namespace net