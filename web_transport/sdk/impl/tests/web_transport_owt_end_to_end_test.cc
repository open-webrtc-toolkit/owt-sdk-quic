/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Reference: net/third_party/quiche/src/quic/core/http/end_to_end_test.cc
 */

#include "base/files/file_path.h"
#include "base/strings/strcat.h"
#include "base/threading/thread.h"
#include "impl/web_transport_owt_client_impl.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/quic/crypto/proof_source_chromium.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/quic/web_transport_client.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quic/core/quic_simple_buffer_allocator.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "owt/quic/web_transport_client_interface.h"
#include "owt/quic/web_transport_factory.h"
#include "owt/quic/web_transport_server_interface.h"
#include "owt/web_transport/sdk/impl/tests/web_transport_echo_visitors.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace owt {
namespace quic {
namespace test {

class ClientMockVisitor : public WebTransportClientInterface::Visitor {
 public:
  MOCK_METHOD0(OnConnected, void());
  MOCK_METHOD0(OnConnectionFailed, void());
  MOCK_METHOD1(OnIncomingStream, void(WebTransportStreamInterface*));
};

class StreamMockVisitor : public WebTransportStreamInterface::Visitor {
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

class WebTransportOwtEndToEndTest : public net::TestWithTaskEnvironment {
 public:
  WebTransportOwtEndToEndTest()
      : io_thread_(std::make_unique<base::Thread>(
            "web_transport_end_to_end_test_io_thread")),
        event_thread_(std::make_unique<base::Thread>(
            "web_transport_end_to_end_event_thread")),
        factory_(std::unique_ptr<WebTransportFactory>(
            WebTransportFactory::CreateForTesting())),
        port_(20001) {
    base::Thread::Options options;
    options.message_pump_type = base::MessagePumpType::IO;
    io_thread_->StartWithOptions(options);
    event_thread_->StartWithOptions(options);
  }

  ~WebTransportOwtEndToEndTest() override {
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

  void StartEchoServer() {
    base::FilePath certs_dir = net::GetTestCertsDirectory();
    server_ = std::unique_ptr<WebTransportServerInterface>(
        factory_->CreateQuicTransportServer(
            port_,
            certs_dir.AppendASCII("quic-short-lived.pem").value().c_str(),
            certs_dir.AppendASCII("quic-leaf-cert.key").value().c_str(),
            certs_dir.AppendASCII("quic-leaf-cert.key.sct").value().c_str()));
    server_visitor_ = std::make_unique<ServerEchoVisitor>();
    server_->SetVisitor(server_visitor_.get());
    server_->Start();
  }

  GURL GetServerUrl(const std::string& suffix) {
    return GURL{base::StrCat(
        {"https://test.example.com:", base::NumberToString(port_), suffix})};
  }

  void Run() {
    run_loop_ = std::make_unique<base::RunLoop>();
    run_loop_->Run();
  }

  auto StopRunning() {
    return [this]() { run_loop_->Quit(); };
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

  std::unique_ptr<WebTransportClientInterface> CreateClient(const GURL& url) {
    base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);
    io_thread_->task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&WebTransportOwtEndToEndTest::InitContextOnIOThread,
                       base::Unretained(this), &done));
    done.Wait();
    net::WebTransportParameters parameters;
    parameters.server_certificate_fingerprints.push_back(
        ::quic::CertificateFingerprint{
            .algorithm = ::quic::CertificateFingerprint::kSha256,
            .fingerprint = "ED:3D:D7:C3:67:10:94:68:D1:DC:D1:26:5C:B2:74:D7:1C:"
                           "A2:63:3E:94:94:C0:84:39:D6:64:FA:08:B9:77:37"});
    // Set clock to a time in which quic-short-lived.pem is valid
    // (2020-06-05T20:35:00.000Z).
    helper_->clock().set_wall_now(
        ::quic::QuicWallTime::FromUNIXSeconds(1591389300));
    return std::unique_ptr<WebTransportClientInterface>(
        new WebTransportOwtClientImpl(url, origin_, parameters, context_.get(),
                                      io_thread_.get(), event_thread_.get()));
  }

 protected:
  std::unique_ptr<base::Thread> io_thread_;
  std::unique_ptr<base::Thread> event_thread_;
  std::unique_ptr<WebTransportFactory> factory_;
  std::unique_ptr<WebTransportServerInterface> server_;
  int port_;
  url::Origin origin_;
  std::unique_ptr<base::RunLoop> run_loop_;
  std::unique_ptr<net::URLRequestContext> context_;
  TestConnectionHelper* helper_;  // Owned by |context_|.
  ClientMockVisitor visitor_;
  std::unique_ptr<WebTransportClientInterface> client_;
  std::unique_ptr<WebTransportServerInterface::Visitor> server_visitor_;
};

TEST_F(WebTransportOwtEndToEndTest, Connect) {
  StartEchoServer();
  client_ = CreateClient(GetServerUrl("/discard"));
  client_->SetVisitor(&visitor_);
  EXPECT_CALL(visitor_, OnConnected()).WillOnce(StopRunning());
  client_->Connect();
  Run();
}

TEST_F(WebTransportOwtEndToEndTest, InvalidCertificate) {
  StartEchoServer();
  std::unique_ptr<WebTransportClientInterface> client =
      std::unique_ptr<WebTransportClientInterface>(
          factory_->CreateQuicTransportClient(
              GetServerUrl("/discard").spec().c_str()));
  client->SetVisitor(&visitor_);
  EXPECT_CALL(visitor_, OnConnectionFailed()).WillOnce(StopRunning());
  client->Connect();
  Run();
}

TEST_F(WebTransportOwtEndToEndTest, EchoBidirectionalStream) {
  StartEchoServer();
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
  EXPECT_EQ(stream->Write(data, data_size), data_size);
  EXPECT_CALL(stream_visitor, OnCanRead()).WillOnce(StopRunning());
  Run();
  EXPECT_EQ(stream->ReadableBytes(), data_size);
  uint8_t* data_read = new uint8_t[data_size];
  stream->Read(data_read, data_size);
  for (size_t i = 0; i < data_size; i++) {
    EXPECT_EQ(data[i], data_read[i]);
  }
}

}  // namespace test
}  // namespace quic
}  // namespace owt