/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * End to end test for QuicTransportOwtClient and QuicTransportSimpleServer.
 * Reference: net/quic/quic_transport_end_to_end_test.cc
 */

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

class QuicTransportOwtEndToEndTest : public net::TestWithTaskEnvironment {
 public:
  QuicTransportOwtEndToEndTest()
      : factory_(std::unique_ptr<QuicTransportFactory>(
            QuicTransportFactory::Create())),
        port_(0),
        origin_(url::Origin::Create(GURL{"https://example.org"})) {}

  std::unique_ptr<QuicTransportClientInterface> CreateClient(
      const std::string& url) {
    return std::unique_ptr<QuicTransportClientInterface>(
        factory_->CreateQuicTransportClient(url.c_str()));
  }

  void StartServer() {
    std::unique_ptr<::quic::ProofSource> proof_source =
        ::quic::test::crypto_test_utils::ProofSourceForTesting();
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

 private:
  std::unique_ptr<QuicTransportFactory> factory_;
  std::unique_ptr<net::QuicTransportSimpleServer> server_;
  int port_;
  url::Origin origin_;
  std::unique_ptr<base::RunLoop> run_loop_;
};

TEST_F(QuicTransportOwtEndToEndTest, Creation) {
  StartServer();
  std::unique_ptr<QuicTransportClientInterface> quic_client =
      CreateClient(GetServerUrl("/discard").spec());
  quic_client->SetVisitor(&visitor_);
  EXPECT_CALL(visitor_, OnConnected()).WillOnce(StopRunning());
  quic_client->Connect();
  Run();
}
}  // namespace test
}  // namespace quic
}  // namespace owt