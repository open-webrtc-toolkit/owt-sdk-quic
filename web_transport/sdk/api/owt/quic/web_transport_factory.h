/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_WEB_TRANSPORT_WEB_TRANSPORT_FACTORY_H_
#define OWT_WEB_TRANSPORT_WEB_TRANSPORT_FACTORY_H_

#include "owt/quic/export.h"
#include "owt/quic/web_transport_client_interface.h"

namespace owt {
namespace quic {

class WebTransportServerInterface;
class WebTransportClientInterface;

class OWT_EXPORT WebTransportFactory {
 public:
  virtual ~WebTransportFactory() = default;

  /// Create a WebTransportFactory.
  static WebTransportFactory* Create();
  /// Create a WebTransportFactory for testing. It will not initialize
  /// AtExitManager since testing tools will initialize one.
  static WebTransportFactory* CreateForTesting();
  // `accepted_origins` is removed at this time because ABI compatible issue.
  // Ownership of returned value is moved to caller. Returns nullptr if creation
  // is failed.
  virtual WebTransportServerInterface* CreateQuicTransportServer(
      int port,
      const char* cert_path,
      const char* key_path,
      const char* secret_path/*,
      std::vector<std::string> accepted_origins*/) = 0;
  virtual WebTransportServerInterface* CreateQuicTransportServer(
      int port,
      const char* pfx_path,
      const char* password) = 0;
  virtual void ReleaseQuicTransportServer(
      const WebTransportServerInterface* server) = 0;
  virtual WebTransportClientInterface* CreateQuicTransportClient(
      const char* url) = 0;
  virtual WebTransportClientInterface* CreateQuicTransportClient(
      const char* url,
      const WebTransportClientInterface::Parameters& parameters) = 0;
};
}  // namespace quic
}  // namespace owt

#endif