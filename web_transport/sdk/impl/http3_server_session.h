/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_WEB_TRANSPORT_HTTP3_SERVER_SESSION_H_
#define OWT_QUIC_WEB_TRANSPORT_HTTP3_SERVER_SESSION_H_

#include "net/third_party/quiche/src/quic/core/http/quic_spdy_session.h"

namespace owt {
namespace quic {
class Http3ServerSession : public ::quic::QuicSpdySession {};
}  // namespace quic
}  // namespace owt

#endif