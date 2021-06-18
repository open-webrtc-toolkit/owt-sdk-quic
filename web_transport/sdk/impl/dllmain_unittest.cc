/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <regex>
#include "owt/quic/web_transport_factory.h"
#include "owt/quic/version.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace owt {
namespace quic {
namespace test {
TEST(DllTest, CreateQuicTransportFactory) {
  auto* factory = owt::quic::WebTransportFactory::Create();
  EXPECT_TRUE(factory != nullptr);
}
}  // namespace test
}  // namespace quic
}  // namespace owt
