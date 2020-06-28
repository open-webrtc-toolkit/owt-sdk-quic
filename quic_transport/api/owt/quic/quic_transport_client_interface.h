/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_QUIC_QUIC_TRANSPORT_CLIENT_INTERFACE_H_
#define OWT_QUIC_QUIC_TRANSPORT_CLIENT_INTERFACE_H_

#include "owt/quic/export.h"
#include "owt/quic/quic_transport_session_interface.h"

namespace owt {
namespace quic {
// A client connects to QuicTransportServer.
class OWT_EXPORT QuicTransportClientInterface {
  virtual void Connect() = 0;
};
}  // namespace quic
}  // namespace owt