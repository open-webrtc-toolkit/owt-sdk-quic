/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * End to end test for QuicTransportOwtClient and QuicTransportSimpleServer.
 * Reference: net/quic/quic_transport_end_to_end_test.cc
 */

#include "net/quic/crypto/proof_source_chromium.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quic/test_tools/crypto_test_utils.h"
#include "net/tools/quic/quic_transport_simple_server.h"
#include "owt/quic/quic_transport_client_interface.h"
#include "owt/quic/quic_transport_factory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace owt {
namespace quic {
namespace test {

class ClientMockVisitor : public QuicTransportClientInterface::Visitor {
 public:
  MOCK_METHOD0(OnConnected, void());
  MOCK_METHOD0(OnConnectionFailed, void());
};

// A clock that only mocks out WallNow(), but uses real Now() and
// ApproximateNow().  Useful for certificate verification.
class TestWallClock : public ::quic::QuicClock {
 public:
  ::quic::QuicTime Now() const override {
    return ::quic::QuicChromiumClock::GetInstance()->Now();
  }
  ::quic::QuicTime ApproximateNow() const override {
    return ::quic::QuicChromiumClock::GetInstance()->ApproximateNow();
  }
  ::quic::QuicWallTime WallNow() const override { return wall_now_; }

  void set_wall_now(::quic::QuicWallTime now) { wall_now_ = now; }

 private:
  ::quic::QuicWallTime wall_now_ = ::quic::QuicWallTime::Zero();
};

class TestConnectionHelper : public ::quic::QuicConnectionHelperInterface {
 public:
  const ::quic::QuicClock* GetClock() const override { return &clock_; }
  ::quic::QuicRandom* GetRandomGenerator() override {
    return ::quic::QuicRandom::GetInstance();
  }
  ::quic::QuicBufferAllocator* GetStreamSendBufferAllocator() override {
    return &allocator_;
  }

  TestWallClock& clock() { return clock_; }

 private:
  TestWallClock clock_;
  ::quic::SimpleBufferAllocator allocator_;
};

class QuicTransportOwtEndToEndTest : public net::TestWithTaskEnvironment {
 public:
  QuicTransportOwtEndToEndTest()
      : factory_(std::unique_ptr<QuicTransportFactory>(
            QuicTransportFactory::Create())),
        port_(0),
        origin_(url::Origin::Create(GURL{"https://example.org"})) {}

  std::unique_ptr<QuicTransportClientInterface> CreateClient(
      const std::string& url) {
  ::quic::QuicTransportClient::Parameters parameters;
  parameters.server_certificate_fingerprints.push_back(
      quic::CertificateFingerprint{
          .algorithm = quic::CertificateFingerprint::kSha256,
          .fingerprint = "ED:3D:D7:C3:67:10:94:68:D1:DC:D1:26:5C:B2:74:D7:1C:"
                         "A2:63:3E:94:94:C0:84:39:D6:64:FA:08:B9:77:37"});
    return std::unique_ptr<QuicTransportClientInterface>(
        factory_->CreateQuicTransportClient(url.c_str(), parameters));
  }

  void StartServer() {
    auto proof_source = std::make_unique<net::ProofSourceChromium>();
    base::FilePath certs_dir = net::GetTestCertsDirectory();
    ASSERT_TRUE(proof_source->Initialize(
        certs_dir.AppendASCII("quic-short-lived.pem"),
        certs_dir.AppendASCII("quic-leaf-cert.key"),
        certs_dir.AppendASCII("quic-leaf-cert.key.sct")));
    server_ = std::make_unique<net::QuicTransportSimpleServer>(
        /* port */ 0, std::vector<url::Origin>({origin_}),
        std::move(proof_source));
    ASSERT_EQ(EXIT_SUCCESS, server_->Start());
    port_ = server_->server_address().port();
  }

  GURL GetServerUrl(const std::string& suffix) {
    return GURL{
        quiche::QuicheStrCat("quic-transport://localhost:", port_, suffix)};
  }

  void Run() {
    run_loop_ = std::make_unique<base::RunLoop>();
    run_loop_->Run();
  }

  auto StopRunning() {
    return [this]() { run_loop_->Quit(); };
  }

 protected:
  ClientMockVisitor visitor_;
  std::unique_ptr<QuicTransportClientInterface> client_;

 private:
  std::unique_ptr<QuicTransportFactory> factory_;
  std::unique_ptr<net::QuicTransportSimpleServer> server_;
  int port_;
  url::Origin origin_;
  std::unique_ptr<base::RunLoop> run_loop_;
};

TEST_F(QuicTransportOwtEndToEndTest, Creation) {
  StartServer();
  client_ = CreateClient(GetServerUrl("/discard"));
  client_->SetVisitor(&visitor_);
  EXPECT_CALL(visitor_, OnConnected()).WillOnce(StopRunning());
  client_->Connect();
  LOG(INFO) << "Before run";
  Run();
  LOG(INFO) << "After run";
}
}  // namespace test
}  // namespace quic
}  // namespace owt