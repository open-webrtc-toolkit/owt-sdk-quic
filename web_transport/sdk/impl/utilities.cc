/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "owt/web_transport/sdk/impl/utilities.h"

namespace owt {
namespace quic {
MessageStatus Utilities::ConvertMessageStatus(
    absl::optional<::quic::MessageStatus> status) {
  if (!status) {
    return MessageStatus::kUnavailable;
  }
  switch (status.value()) {
    case ::quic::MESSAGE_STATUS_SUCCESS:
      return MessageStatus::kSuccess;
    case ::quic::MESSAGE_STATUS_ENCRYPTION_NOT_ESTABLISHED:
      return MessageStatus::kEncryptionNotEstablished;
    case ::quic::MESSAGE_STATUS_UNSUPPORTED:
      return MessageStatus::kUnsupported;
    case ::quic::MESSAGE_STATUS_BLOCKED:
      return MessageStatus::kBlocked;
    case ::quic::MESSAGE_STATUS_TOO_LARGE:
      return MessageStatus::kTooLarge;
    case ::quic::MESSAGE_STATUS_INTERNAL_ERROR:
      return MessageStatus::kInternalError;
    default:
      return MessageStatus::kUnavailable;
  }
}
}  // namespace quic
}  // namespace owt