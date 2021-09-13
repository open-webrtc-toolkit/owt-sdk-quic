/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_WEB_TRANSPORT_LOGGING_H_
#define OWT_WEB_TRANSPORT_LOGGING_H_

#include "export.h"

namespace owt {
namespace quic {

enum class LoggingSeverity : int {
  /// This level is for data which we do not want to appear in the normal debug
  /// log, but should appear in diagnostic logs.
  kVerbose,
  /// Chatty level used in debugging for all sorts of things, the default in
  /// debug builds.
  kInfo,
  /// Something that may warrant investigation.
  kWarning,
  /// Something that should not have occurred.
  kError,
  /// Fatal errors.
  kFatal
};

class OWT_EXPORT Logging {
 public:
  /// Set logging severity. All logging messages with higher severity will be
  /// logged.
  static void Severity(LoggingSeverity severity);
  /// Get current logging severity.
  static LoggingSeverity Severity();
  // Init logging module.
  static void InitLogging();

 private:
  static LoggingSeverity min_severity_;
};

}  // namespace quic
}  // namespace owt

#endif