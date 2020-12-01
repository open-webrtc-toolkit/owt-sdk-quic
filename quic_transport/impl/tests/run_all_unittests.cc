/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/bind.h"
#include "base/test/launcher/unit_test_launcher.h"
#include "net/socket/transport_client_socket_pool.h"
#include "net/test/net_test_suite.h"

int main(int argc, char** argv) {
  NetTestSuite test_suite(argc, argv);
  net::TransportClientSocketPool::set_connect_backup_jobs_enabled(false);

  return base::LaunchUnitTests(
      argc, argv,
      base::BindOnce(&NetTestSuite::Run, base::Unretained(&test_suite)));
}
