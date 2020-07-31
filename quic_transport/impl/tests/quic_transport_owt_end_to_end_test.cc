/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * End to end test for QuicTransportOwtClient and QuicTransportSimpleServer.
 * Reference: net/quic/quic_transport_end_to_end_test.cc
 */

#include "base/threading/thread.h"
#include "net/base/host_port_pair.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/quic/crypto/proof_source_chromium.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_transport_client.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quic/test_tools/crypto_test_utils.h"
#include "net/tools/quic/quic_transport_simple_server.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "owt/quic/quic_transport_client_interface.h"
#include "owt/quic/quic_transport_factory.h"
#include "owt/quic/quic_transport_stream_interface.h"
#include "owt/quic_transport/impl/quic_transport_owt_client_impl.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace owt {
namespace quic {
namespace test {

class ClientMockVisitor : public QuicTransportClientInterface::Visitor {
 public:
  MOCK_METHOD0(OnConnected, void());
  MOCK_METHOD0(OnConnectionFailed, void());
  MOCK_METHOD1(OnIncomingStream, void(QuicTransportStreamInterface*));
};

class StreamMockVisitor : public QuicTransportStreamInterface::Visitor {
 public:
  MOCK_METHOD0(OnCanRead, void());
  MOCK_METHOD0(OnCanWrite, void());
  MOCK_METHOD0(OnFinRead, void());
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
      : io_thread_(std::make_unique<base::Thread>(
            "quic_transport_end_to_end_test_io_thread")),
        factory_(std::unique_ptr<QuicTransportFactory>(
            QuicTransportFactory::Create())),
        port_(0),
        origin_(url::Origin::Create(GURL{"https://example.org"})) {
    base::Thread::Options options;
    options.message_pump_type = base::MessagePumpType::IO;
    io_thread_->StartWithOptions(options);
  }

  ~QuicTransportOwtEndToEndTest() override {
    client_.reset();
    base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);
    io_thread_->task_runner()->PostTask(
        FROM_HERE, base::BindOnce(
                       [](std::unique_ptr<net::URLRequestContext> context,
                          base::WaitableEvent* event) {
                         context.reset();
                         event->Signal();
                       },
                       std::move(context_), &done));
    done.Wait();
  }

  void InitContextOnIOThread(base::WaitableEvent* event) {
    net::URLRequestContextBuilder builder;
    builder.set_proxy_resolution_service(
        net::ConfiguredProxyResolutionService::CreateDirect());
    auto helper = std::make_unique<TestConnectionHelper>();
    helper_ = helper.get();
    auto quic_context = std::make_unique<net::QuicContext>(std::move(helper));
    quic_context->params()->origins_to_force_quic_on.insert(
        net::HostPortPair("test.example.com", 0));
    builder.set_quic_context(std::move(quic_context));
    context_ = builder.Build();
    event->Signal();
  }

  std::unique_ptr<QuicTransportClientInterface> CreateClient(const GURL& url) {
    base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);
    io_thread_->task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&QuicTransportOwtEndToEndTest::InitContextOnIOThread,
                       base::Unretained(this), &done));
    done.Wait();
    net::QuicTransportClient::Parameters parameters;
    parameters.server_certificate_fingerprints.push_back(
        ::quic::CertificateFingerprint{
            .algorithm = ::quic::CertificateFingerprint::kSha256,
            .fingerprint = "ED:3D:D7:C3:67:10:94:68:D1:DC:D1:26:5C:B2:74:D7:1C:"
                           "A2:63:3E:94:94:C0:84:39:D6:64:FA:08:B9:77:37"});
    // Set clock to a time in which quic-short-lived.pem is valid
    // (2020-06-05T20:35:00.000Z).
    helper_->clock().set_wall_now(
        ::quic::QuicWallTime::FromUNIXSeconds(1591389300));
    return std::unique_ptr<QuicTransportClientInterface>(
        new QuicTransportOwtClientImpl(url, origin_, parameters, context_.get(),
                                       io_thread_.get()));
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
    return GURL{quiche::QuicheStrCat(
        "quic-transport://test.example.com:", port_, suffix)};
  }

  void Run() {
    run_loop_ = std::make_unique<base::RunLoop>();
    run_loop_->Run();
  }

  auto StopRunning() {
    return [this]() { run_loop_->Quit(); };
  }

 protected:
  std::unique_ptr<base::Thread> io_thread_;
  std::unique_ptr<QuicTransportFactory> factory_;
  std::unique_ptr<net::QuicTransportSimpleServer> server_;
  int port_;
  url::Origin origin_;
  std::unique_ptr<base::RunLoop> run_loop_;
  std::unique_ptr<net::URLRequestContext> context_;
  TestConnectionHelper* helper_;  // Owned by |context_|.
  ClientMockVisitor visitor_;
  std::unique_ptr<QuicTransportClientInterface> client_;
};

TEST_F(QuicTransportOwtEndToEndTest, Connect) {
  StartServer();
  client_ = CreateClient(GetServerUrl("/discard"));
  client_->SetVisitor(&visitor_);
  EXPECT_CALL(visitor_, OnConnected()).WillOnce(StopRunning());
  client_->Connect();
  Run();
}

TEST_F(QuicTransportOwtEndToEndTest, InvalidCertificate) {
  StartServer();
  std::unique_ptr<QuicTransportClientInterface> client =
      std::unique_ptr<QuicTransportClientInterface>(
          factory_->CreateQuicTransportClient(
              GetServerUrl("/discard").spec().c_str()));
  client->SetVisitor(&visitor_);
  EXPECT_CALL(visitor_, OnConnectionFailed()).WillOnce(StopRunning());
  client->Connect();
  Run();
}

TEST_F(QuicTransportOwtEndToEndTest, EchoBidirectionalStream) {
  StartServer();
  client_ = CreateClient(GetServerUrl("/echo"));
  client_->SetVisitor(&visitor_);
  EXPECT_CALL(visitor_, OnConnected()).WillOnce(StopRunning());
  client_->Connect();
  Run();
  StreamMockVisitor stream_visitor;
  auto* stream = client_->CreateBidirectionalStream();
  EXPECT_TRUE(stream != nullptr);
  stream->SetVisitor(&stream_visitor);
  size_t data_size = 10;
  uint8_t* data = new uint8_t[data_size];
  for (size_t i = 0; i < data_size; i++) {
    data[i] = i;
  }
  stream->Write(data, data_size);
  EXPECT_CALL(stream_visitor, OnCanRead()).WillOnce(StopRunning());
  Run();
  EXPECT_EQ(stream->ReadableBytes(), data_size);
  uint8_t* data_read = new uint8_t[data_size];
  stream->Read(data_read, data_size);
  for (size_t i = 0; i < data_size; i++) {
    EXPECT_EQ(data[i], data_read[i]);
  }
}

TEST_F(QuicTransportOwtEndToEndTest, EchoUnidirectionalStream) {
  StartServer();
  client_ = CreateClient(GetServerUrl("/echo"));
  client_->SetVisitor(&visitor_);
  EXPECT_CALL(visitor_, OnConnected()).WillOnce(StopRunning());
  client_->Connect();
  Run();
  auto* stream = client_->CreateOutgoingUnidirectionalStream();
  EXPECT_TRUE(stream != nullptr);
  size_t data_size = 10;
  uint8_t* data = new uint8_t[data_size];
  for (size_t i = 0; i < data_size; i++) {
    data[i] = i;
  }
  stream->Write(data, data_size);
  // For unidirectional streams, QuicTransportSimpleServer echos after stream is
  // closed.
  stream->Close();
  QuicTransportStreamInterface* receive_stream(nullptr);
  EXPECT_CALL(visitor_, OnIncomingStream)
      .WillOnce(DoAll(testing::SaveArg<0>(&receive_stream), StopRunning()));
  Run();
  EXPECT_TRUE(receive_stream != nullptr);
  EXPECT_EQ(receive_stream->ReadableBytes(), data_size);
  uint8_t* data_read = new uint8_t[data_size];
  receive_stream->Read(data_read, data_size);
  for (size_t i = 0; i < data_size; i++) {
    EXPECT_EQ(data[i], data_read[i]);
  }
}

}  // namespace test
}  // namespace quic
}  // namespace owt