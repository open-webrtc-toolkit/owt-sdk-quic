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
#include "net/third_party/quiche/src/quic/core/crypto/proof_source.h"

namespace owt {
namespace quic {

// ProofSourceOwt could be initialized with a PKCS12 file. OWT conference server
// stores certificate and key in this format.
class ProofSourceOwt : public ::quic::ProofSource {
 public:
  ProofSourceOwt();
  ~ProofSourceOwt() override;
  ProofSourceOwt& operator=(ProofSourceOwt&) = delete;
  // Initializes this object based on a pfx file.
  bool Initialize(const base::FilePath& pfx_path, const std::string& password);

  // Overrides quic::ProofSource.
  void GetProof(const ::quic::QuicSocketAddress& server_address,
                const ::quic::QuicSocketAddress& client_address,
                const std::string& hostname,
                const std::string& server_config,
                ::quic::QuicTransportVersion quic_version,
                absl::string_view chlo_hash,
                std::unique_ptr<Callback> callback) override;

  ::quic::QuicReferenceCountedPointer<::quic::ProofSource::Chain> GetCertChain(
      const ::quic::QuicSocketAddress& server_address,
      const ::quic::QuicSocketAddress& client_address,
      const std::string& hostname,
      bool* cert_matched_sni) override;

  void ComputeTlsSignature(
      const ::quic::QuicSocketAddress& server_address,
      const ::quic::QuicSocketAddress& client_address,
      const std::string& hostname,
      uint16_t signature_algorithm,
      absl::string_view in,
      std::unique_ptr<SignatureCallback> callback) override;

  absl::InlinedVector<uint16_t, 8> SupportedTlsSignatureAlgorithms()
      const override;

  TicketCrypter* GetTicketCrypter() override;
  void SetTicketCrypter(std::unique_ptr<TicketCrypter> ticket_crypter);

 private:
  bool GetProofInner(
      const ::quic::QuicSocketAddress& server_ip,
      const std::string& hostname,
      const std::string& server_config,
      ::quic::QuicTransportVersion quic_version,
      absl::string_view chlo_hash,
      ::quic::QuicReferenceCountedPointer<::quic::ProofSource::Chain>*
          out_chain,
      ::quic::QuicCryptoProof* proof);

  std::unique_ptr<::quic::CertificatePrivateKey> private_key_;
  std::vector<scoped_refptr<net::X509Certificate>> certs_in_file_;
  ::quic::QuicReferenceCountedPointer<::quic::ProofSource::Chain> chain_;
  std::unique_ptr<::quic::ProofSource::TicketCrypter> ticket_crypter_;
};

}  // namespace quic
}  // namespace owt

#endif