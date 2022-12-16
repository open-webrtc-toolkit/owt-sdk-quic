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

#include "owt/quic_transport/sdk/impl/proof_source_owt.h"
#include "base/files/file_util.h"
#include "base/strings/string_number_conversions.h"
#include "crypto/openssl_util.h"
#include "net/cert/x509_util.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/crypto_protocol.h"
#include "third_party/boringssl/src/include/openssl/base.h"
#include "third_party/boringssl/src/include/openssl/pkcs8.h"
#include "third_party/boringssl/src/include/openssl/stack.h"

namespace quic {

ProofSourceOwt::ProofSourceOwt() {}

ProofSourceOwt::~ProofSourceOwt() {}

ProofSource::TicketCrypter* ProofSourceOwt::GetTicketCrypter() {
  return nullptr;
}

void ProofSourceOwt::GetProof(const QuicSocketAddress& server_address,
                              const QuicSocketAddress& client_address,
                              const std::string& hostname,
                              const std::string& server_config,
                              QuicTransportVersion quic_version,
                              absl::string_view chlo_hash,
                              std::unique_ptr<Callback> callback) {
  bool cert_matched_sni;
  ::quiche::QuicheReferenceCountedPointer<ProofSource::Chain> chain =
      GetCertChain(server_address, client_address, hostname, &cert_matched_sni);
  QuicCryptoProof proof;
  proof.signature = "fake signature";
  proof.leaf_cert_scts = "fake timestamp";
  callback->Run(true, chain, proof, nullptr);
}

::quiche::QuicheReferenceCountedPointer<ProofSource::Chain>
ProofSourceOwt::GetCertChain(const QuicSocketAddress& server_address,
                             const QuicSocketAddress& client_address,
                             const std::string& hostname,
			     bool* cert_matched_sni) {
  std::vector<std::string> certs;
  certs.push_back("fake cert");
  return ::quiche::QuicheReferenceCountedPointer<ProofSource::Chain>(
      new ProofSource::Chain(certs));
}

void ProofSourceOwt::ComputeTlsSignature(
    const QuicSocketAddress& server_address,
    const QuicSocketAddress& client_address,
    const std::string& hostname,
    uint16_t signature_algorithm,
    absl::string_view in,
    std::unique_ptr<SignatureCallback> callback) {
  callback->Run(true, "fake signature", nullptr);
}

}  // namespace quic
