/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_WEB_TRANSPORT_WEB_TRANSPORT_FACTORY_IMPL_H_
#define OWT_WEB_TRANSPORT_WEB_TRANSPORT_FACTORY_IMPL_H_

#include <memory>
#include <string>
#include <vector>
#include "owt/quic/export.h"
#include "owt/quic/web_transport_factory.h"

namespace quic {
class QuicAlarmFactory;
class QuicConnectionHelperInterface;
class QuicClock;
class QuicRandom;
class QuicCompressedCertsCache;
class QuicCryptoServerConfig;
class ProofSource;
}  // namespace quic

namespace base {
class Thread;
class AtExitManager;
}  // namespace base

namespace owt {
namespace quic {

class OWT_EXPORT WebTransportFactoryImpl : public WebTransportFactory {
 public:
  WebTransportFactoryImpl();
  ~WebTransportFactoryImpl() override;
  void InitializeAtExitManager();
  // `accepted_origins` is removed at this time because ABI compatible issue.
  WebTransportServerInterface* CreateWebTransportServer(
      int port,
      const char* cert_path,
      const char* key_path,
      const char* secret_path) override;
  WebTransportServerInterface* CreateWebTransportServer(
      int port,
      const char* pfx_path,
      const char* password) override;
  WebTransportClientInterface* CreateWebTransportClient(
      const char* url) override;
  WebTransportClientInterface* CreateWebTransportClient(
      const char* url,
      const WebTransportClientInterface::Parameters& parameters) override;

 private:
  void Init();

  std::unique_ptr<base::AtExitManager> at_exit_manager_;
  std::unique_ptr<base::Thread> io_thread_;
  std::unique_ptr<base::Thread> event_thread_;
};

}  // namespace quic
}  // namespace owt

#endif