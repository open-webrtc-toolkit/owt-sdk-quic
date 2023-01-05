/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "owt/quic/logging.h"
#include <unordered_map>
#include "base/logging.h"

namespace owt {
namespace quic {

#ifdef _DEBUG
LoggingSeverity Logging::min_severity_ = LoggingSeverity::kInfo;
#else
LoggingSeverity Logging::min_severity_ = LoggingSeverity::kError;
#endif

// Due to a defect in C++ 11, static cast to int instead of enum value.
// http://www.open-std.org/jtc1/sc22/wg21/docs/lwg-defects.html#2148
static std::unordered_map<int, logging::LogSeverity> logging_severity_map = {
    {static_cast<int>(LoggingSeverity::kVerbose), logging::LOG_VERBOSE},
    {static_cast<int>(LoggingSeverity::kInfo), logging::LOG_INFO},
    {static_cast<int>(LoggingSeverity::kWarning), logging::LOG_WARNING},
    {static_cast<int>(LoggingSeverity::kError), logging::LOG_ERROR},
    {static_cast<int>(LoggingSeverity::kFatal), logging::LOG_FATAL}};

void Logging::Severity(LoggingSeverity severity) {
  min_severity_ = severity;
  LOG(ERROR) << "Setting logging level to "
             << logging_severity_map[static_cast<int>(severity)];
  logging::SetMinLogLevel(logging_severity_map[static_cast<int>(severity)]);
}

LoggingSeverity Logging::Severity() {
  return min_severity_;
}

void Logging::InitLogging() {
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_STDERR;
  logging::InitLogging(settings);
}

}  // namespace quic
}  // namespace owt