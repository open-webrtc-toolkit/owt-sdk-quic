/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_TRANSPORT_VERSION_H_
#define OWT_QUIC_TRANSPORT_VERSION_H_

namespace owt {
namespace quic {

class Version {
  // Get current product version number.
  static const char* VersionNumber();
  // Get last commit hash.
  static const char* LastChange();
};

}  // namespace quic
}  // namespace owt

#endif