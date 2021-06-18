/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Most classes in this file and its implementations are borrowed from
// Chromium/net/third_party/quiche/src/quic/tools/quic_simple_server_stream.cc
// with modifications.

#include "impl/web_transport_server_stream.h"

namespace owt {
namespace quic {

WebTransportServerStream::WebTransportServerStream(
    ::quic::WebTransportStream* stream,
    base::SingleThreadTaskRunner* io_runner,
    base::SingleThreadTaskRunner* event_runner)
    : stream_(stream), io_runner_(io_runner), event_runner_(event_runner) {
  CHECK(stream_);
  CHECK(io_runner_);
  CHECK(event_runner_);
}

WebTransportServerStream::~WebTransportServerStream() {}

}  // namespace quic
}  // namespace owt