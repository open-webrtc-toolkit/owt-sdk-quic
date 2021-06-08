/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "owt/quic/version.h"
#include <string>
#include "owt/web_transport/version_info_values.h"

namespace owt {
namespace quic {

constexpr char kProductVersion[] = PRODUCT_VERSION;
constexpr char kLastChange[] = LAST_CHANGE;

const char* Version::VersionNumber() {
  return kProductVersion;
}

const char* Version::LastChange() {
  return kLastChange;
}

}  // namespace quic
}  // namespace owt