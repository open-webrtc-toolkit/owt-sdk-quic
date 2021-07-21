/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Similar to net/third_party/quiche/src/quic/tools/quic_client_bin.cc, but it
// only connects to a WebTransport server.

#include <string>
#include <vector>
#include "base/logging.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_system_event_loop.h"
#include "owt/quic/web_transport_factory.h"

DEFINE_QUIC_COMMAND_LINE_FLAG(std::string,
                              fingerprint,
                              "",
                              "Certificate fingerprint.");

int main(int argc, char* argv[]) {
  QuicSystemEventLoop event_loop("quic_client");
  const char* usage = "Usage: owt_web_transport_test_client [options] <url>";

  // All non-flag arguments should be interpreted as URLs to fetch.
  std::vector<std::string> urls =
      ::quic::QuicParseCommandLineFlags(usage, argc, argv);
  if (urls.size() != 1) {
    LOG(ERROR) << "Url size is " << urls.size();
    ::quic::QuicPrintCommandLineFlagHelp(usage);
    exit(0);
  }
  LOG(INFO) << "Connecting to " << urls[0];
  std::string fingerprint(GetQuicFlag(FLAGS_fingerprint));
  owt::quic::WebTransportClientInterface::Parameters parameters;
  if (fingerprint.empty()) {
    parameters.server_certificate_fingerprints_length = 0;
  } else {
    parameters.server_certificate_fingerprints_length = 1;
    auto* fingerprints = new owt::quic::CertificateFingerprint[1];
    fingerprints[0].fingerprint = fingerprint.c_str();
    parameters.server_certificate_fingerprints = &fingerprints;
  }
  std::unique_ptr<owt::quic::WebTransportFactory> factory_(
      owt::quic::WebTransportFactory::CreateForTesting());
  std::unique_ptr<owt::quic::WebTransportClientInterface> client_(
      factory_->CreateWebTransportClient(urls[0].c_str(), parameters));
  client_->Connect();
}