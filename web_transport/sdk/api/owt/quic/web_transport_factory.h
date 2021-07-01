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
  // Create a WebTransport over HTTP/3 server with certificate, key and secret
  // file. Ownership of returned value is moved to caller. Returns nullptr if
  // creation is failed.
  virtual WebTransportServerInterface* CreateWebTransportServer(
      int port,
      const char* cert_path,
      const char* key_path,
      const char* secret_path) = 0;
  // Create a WebTransport over HTTP/3 server with pkcs12 file. Ownership of
  // returned value is moved to caller. Returns nullptr if creation is failed.
  virtual WebTransportServerInterface* CreateWebTransportServer(
      int port,
      const char* pfx_path,
      const char* password) = 0;
  // Create a WebTransport over HTTP/3 client. It will not connect to the given
  // `url` immediately after creation.
  virtual WebTransportClientInterface* CreateWebTransportClient(
      const char* url) = 0;
  // Create a WebTransport over HTTP/3 client with parameters. It will not
  // connect to the given `url` immediately after creation.
  virtual WebTransportClientInterface* CreateWebTransportClient(
      const char* url,
      const WebTransportClientInterface::Parameters& parameters) = 0;
};
}  // namespace quic
}  // namespace owt

#endif