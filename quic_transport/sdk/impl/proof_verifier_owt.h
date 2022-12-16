/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This class is similar to net/quic/crypto/proof_source_chromium.h, but it
// accepts PKCS12 file as input.

#ifndef OWT_WEB_TRANSPORT_PROOF_SOURCE_OWT_H_
#define OWT_WEB_TRANSPORT_PROOF_SOURCE_OWT_H_

#include "base/files/file_path.h"
#include "crypto/rsa_private_key.h"
#include "net/cert/x509_certificate.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/proof_verifier.h"

namespace quic {
using std::endl;
using std::string;

// ProofSourceOwt could be initialized with a PKCS12 file. OWT conference server
// stores certificate and key in this format.
class ProofVerifierOwt : public ProofVerifier {
 public:
  ProofVerifierOwt();
  ~ProofVerifierOwt() override;
  ProofVerifierOwt& operator=(ProofVerifierOwt&) = delete;
  
  // Overrides quic::ProofVerifer.
  QuicAsyncStatus VerifyProof(
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
      std::unique_ptr<ProofVerifierCallback> callback) override;

  QuicAsyncStatus VerifyCertChain(
      const std::string& hostname,
      const uint16_t port,
      const std::vector<std::string>& certs,
      const std::string& ocsp_response,
      const std::string& cert_sct,
      const ProofVerifyContext* verify_context,
      std::string* error_details,
      std::unique_ptr<ProofVerifyDetails>* verify_details,
      uint8_t* out_alert,
      std::unique_ptr<ProofVerifierCallback> callback) override;

  std::unique_ptr<ProofVerifyContext> CreateDefaultContext() override;
};

}  // namespace quic

#endif
