/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This class is similar to net/quic/crypto/proof_source_chromium.cc, but it
// accepts PKCS12 file as input.

#include "owt/quic_transport/sdk/impl/proof_verifier_owt.h"
#include "base/files/file_util.h"
#include "base/strings/string_number_conversions.h"
#include "crypto/openssl_util.h"
#include "net/cert/x509_util.h"
#include "net/third_party/quiche/src/quic/core/crypto/crypto_protocol.h"
#include "third_party/boringssl/src/include/openssl/base.h"
#include "third_party/boringssl/src/include/openssl/pkcs8.h"
#include "third_party/boringssl/src/include/openssl/stack.h"

namespace quic {

ProofVerifierOwt::ProofVerifierOwt() {}

ProofVerifierOwt::~ProofVerifierOwt() {}

QuicAsyncStatus ProofVerifierOwt::VerifyProof(
      const string& hostname,
      const uint16_t port,
      const string& server_config,
      QuicTransportVersion quic_version,
      absl::string_view  chlo_hash,
      const std::vector<string>& certs,
      const string& cert_sct,
      const string& signature,
      const ProofVerifyContext* context,
      string* error_details,
      std::unique_ptr<ProofVerifyDetails>* details,
      std::unique_ptr<ProofVerifierCallback> callback) {
    return QUIC_SUCCESS;
  }

  QuicAsyncStatus ProofVerifierOwt::VerifyCertChain(
      const std::string& hostname,
      const uint16_t port,
      const std::vector<std::string>& certs,
      const std::string& ocsp_response,
      const std::string& cert_sct,
      const ProofVerifyContext* verify_context,
      std::string* error_details,
      std::unique_ptr<ProofVerifyDetails>* verify_details,
      uint8_t* out_alert,
      std::unique_ptr<ProofVerifierCallback> callback) {
    return QUIC_SUCCESS;
  }

  std::unique_ptr<ProofVerifyContext> ProofVerifierOwt::CreateDefaultContext() {
    return nullptr;
  } 

}  // namespace quic
