/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "owt/quic/version.h"
#include <regex>
#include "base/logging.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace owt {
namespace quic {
namespace test {

TEST(VersionTest, GetVersionNumber) {
  // Version number should be `x.x.x.x`, e.g.: `1.1.0.0`.
  std::regex expected_version_number_regex("^([0-9]+\\.){3}\\d+$");
  auto* version_number = owt::quic::Version::VersionNumber();
  EXPECT_TRUE(std::regex_match(version_number, expected_version_number_regex));
}

TEST(VersionTest, GetLastChange) {
  // Last change is a commit ID.
  std::regex expected_last_change_regex("^[0-9a-f]{40}$");
  auto* last_change = owt::quic::Version::LastChange();
  LOG(INFO) << last_change;
  EXPECT_TRUE(std::regex_match(last_change, expected_last_change_regex));
}

}  // namespace test
}  // namespace quic
}  // namespace owt