/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_TRANSPORT_FACTORY_H_
#define OWT_QUIC_TRANSPORT_FACTORY_H_

#include "owt/quic/export.h"

namespace owt {
namespace quic {

class QuicTransportServerInterface;
class QuicTransportClientInterface;

class OWT_EXPORT QuicTransportFactory {
 public:
  virtual ~QuicTransportFactory() = default;

  /// Create a WebTransportFactory.
  static QuicTransportFactory* Create();
  /// Create a WebTransportFactory for testing. It will not initialize
  /// AtExitManager since testing tools will initialize one.
  static QuicTransportFactory* CreateForTesting();
  // Create a WebTransport over HTTP/3 server with certificate, key and secret
  // file. Ownership of returned value is moved to caller. Returns nullptr if
  // creation is failed.
  virtual QuicTransportServerInterface* CreateQuicTransportServer(
      int port,
      const char* cert_file,
      const char* key_file) = 0;
  // Create a WebTransport over HTTP/3 client. It will not connect to the given
  // `url` immediately after creation.
  virtual QuicTransportClientInterface* CreateQuicTransportClient(
      const char* host,
      int port) = 0;
};
}  // namespace quic
}

#endif