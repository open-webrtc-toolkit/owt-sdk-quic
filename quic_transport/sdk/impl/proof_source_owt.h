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

#ifndef QUIC_TRANSPORT_PROOF_SOURCE_OWT_H_
#define QUIC_TRANSPORT_PROOF_SOURCE_OWT_H_

#include "base/files/file_path.h"
#include "crypto/rsa_private_key.h"
#include "net/cert/x509_certificate.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/proof_source.h"

namespace quic {

// ProofSourceOwt could be initialized with a PKCS12 file. OWT conference server
// stores certificate and key in this format.
class ProofSourceOwt : public ProofSource {
 public:
  ProofSourceOwt();
  ~ProofSourceOwt() override;
  ProofSourceOwt& operator=(ProofSourceOwt&) = delete;

  // Overrides quic::ProofSource.
  void GetProof(const QuicSocketAddress& server_address,
                const QuicSocketAddress& client_address,
                const std::string& hostname,
                const std::string& server_config,
                QuicTransportVersion quic_version,
                absl::string_view chlo_hash,
                std::unique_ptr<Callback> callback) override;

  ::quiche::QuicheReferenceCountedPointer<ProofSource::Chain> GetCertChain(
      const QuicSocketAddress& server_address,
      const QuicSocketAddress& client_address,
      const std::string& hostname,
      bool* cert_matched_sni) override;

  void ComputeTlsSignature(
      const QuicSocketAddress& server_address,
      const QuicSocketAddress& client_address,
      const std::string& hostname,
      uint16_t signature_algorithm,
      absl::string_view in,
      std::unique_ptr<SignatureCallback> callback) override;

  TicketCrypter* GetTicketCrypter() override;
};

}  // namespace quic

#endif
