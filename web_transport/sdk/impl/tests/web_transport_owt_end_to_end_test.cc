/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Reference: net/third_party/quiche/src/quic/core/http/end_to_end_test.cc
 */

#include "base/files/file_path.h"
#include "base/strings/strcat.h"
#include "net/quic/crypto/proof_source_chromium.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quic/core/quic_dispatcher.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_test_backend.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_test_server.h"
#include "net/third_party/quiche/src/quic/test_tools/server_thread.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_dispatcher_peer.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_server_peer.h"

namespace owt {
namespace quic {
namespace test {
class WebTransportOwtEndToEndTest : public net::TestWithTaskEnvironment {
 public:
  WebTransportOwtEndToEndTest() {}
  void StartServer() {
    auto proof_source = std::make_unique<net::ProofSourceChromium>();
    base::FilePath certs_dir = net::GetTestCertsDirectory();
    ASSERT_TRUE(proof_source->Initialize(
        certs_dir.AppendASCII("quic-short-lived.pem"),
        certs_dir.AppendASCII("quic-leaf-cert.key"),
        certs_dir.AppendASCII("quic-leaf-cert.key.sct")));
    auto* test_server = new ::quic::test::QuicTestServer(
        std::move(proof_source), server_config_, server_supported_versions_,
        &memory_cache_backend_, expected_server_connection_id_length_);
    server_thread_ = std::make_unique<::quic::test::ServerThread>(
        test_server, server_address_);
    server_thread_->Initialize();
    server_address_ = ::quic::QuicSocketAddress(server_address_.host(),
                                                server_thread_->GetPort());
    server_thread_->Start();
  }
  std::unique_ptr<::quic::test::ServerThread> server_thread_;
  ::quic::QuicSocketAddress server_address_;
  ::quic::test::QuicTestBackend memory_cache_backend_;
  ::quic::QuicConfig server_config_;
  ::quic::ParsedQuicVersionVector server_supported_versions_;
  uint8_t expected_server_connection_id_length_;
};

TEST_F(WebTransportOwtEndToEndTest, Connect) {
  StartServer();
}

}  // namespace test
}  // namespace quic
}  // namespace owt