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
#include "net/third_party/quiche/src/quic/test_tools/quic_dispatcher_peer.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_server_peer.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_test_backend.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_test_server.h"
#include "owt/quic/web_transport_factory.h"
#include "owt/quic/web_transport_server_interface.h"

namespace owt {
namespace quic {
namespace test {

class WebTransportOwtEndToEndTest : public net::TestWithTaskEnvironment {
 public:
  WebTransportOwtEndToEndTest()
      : factory_(std::unique_ptr<WebTransportFactory>(
            WebTransportFactory::CreateForTesting())) {}
  void StartServer() {
    base::FilePath certs_dir = net::GetTestCertsDirectory();
    auto* wt_server = factory_->CreateQuicTransportServer(
        20001, certs_dir.AppendASCII("quic-short-lived.pem").value().c_str(),
        certs_dir.AppendASCII("quic-leaf-cert.key").value().c_str(),
        certs_dir.AppendASCII("quic-leaf-cert.key.sct").value().c_str());
    wt_server->Start();
  }
  std::unique_ptr<WebTransportFactory> factory_;
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