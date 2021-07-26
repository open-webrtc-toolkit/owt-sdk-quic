/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_WEB_TRANSPORT_UTILITIES_H_
#define OWT_WEB_TRANSPORT_UTILITIES_H_

#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "owt/quic/web_transport_definitions.h"

namespace owt {
namespace quic {
class Utilities {
 public:
  static MessageStatus ConvertMessageStatus(
      absl::optional<::quic::MessageStatus> status);
};
}  // namespace quic
}  // namespace owt

#endif