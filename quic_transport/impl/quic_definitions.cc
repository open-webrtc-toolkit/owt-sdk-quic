/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "owt/quic/quic_definitions.h"

namespace owt {
namespace quic{
RTCDtlsFingerprint::RTCDtlsFingerprint() = default;
RTCDtlsFingerprint::~RTCDtlsFingerprint() = default;

RTCQuicParameters::RTCQuicParameters() = default;
RTCQuicParameters::~RTCQuicParameters() = default;
RTCQuicParameters::RTCQuicParameters(const RTCQuicParameters&) = default;
}
}  // namespace owt