/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "net\test\test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace owt {
namespace quic {
namespace test {
  class QuicTransportOwtEndToEndTest:public net::TestWithTaskEnvironment{

  };
}
}  // namespace quic
}  // namespace owt