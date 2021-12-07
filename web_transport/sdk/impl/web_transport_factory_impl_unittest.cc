/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "owt/quic/web_transport_factory.h"
#include "owt/web_transport/sdk/impl/web_transport_factory_impl.h"
#include "base/logging.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace owt {
namespace quic {
namespace test {

// Disabled because the certificate path is hard coded.
TEST(DISABLED_WebTransportFactoryImplTest, CreateWebTransportServer) {
  auto* factory = WebTransportFactory::Create();
  EXPECT_TRUE(factory != nullptr);
  auto* server = factory->CreateWebTransportServer(20001, "", "", "");
  EXPECT_TRUE(server != nullptr);
}

}  // namespace test
}  // namespace quic
}  // namespace owt