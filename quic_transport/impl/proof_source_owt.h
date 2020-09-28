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

#ifndef OWT_QUIC_TRANSPORT_PROOF_SOURCE_OWT_H_
#define OWT_QUIC_TRANSPORT_PROOF_SOURCE_OWT_H_

#include "crypto/rsa_private_key.h"
#include "net/third_party/quiche/src/quic/core/crypto/proof_source.h"

namespace owt {
namespace quic {

// ProofSourceOwt could be initialized with a PKCS12 file. OWT conference server
// stores certificate and key in this format.
class ProofSourceOwt : public ::quic::ProofSource {
 public:
  ProofSourceOwt();
  ~ProofSourceOwt() override;
  // Initializes this object based on a pfx file.
  bool Initialize(const base::FilePath& pfx_path, const std::string& password);

  // Overrides quic::ProofSource.
  void GetProof(const ::quic::QuicSocketAddress& server_address,
                const ::quic::QuicSocketAddress& client_address,
                const std::string& hostname,
                const std::string& server_config,
                ::quic::QuicTransportVersion quic_version,
                quiche::QuicheStringPiece chlo_hash,
                std::unique_ptr<Callback> callback) override;

  ::quic::QuicReferenceCountedPointer<::quic::ProofSource::Chain> GetCertChain(
      const ::quic::QuicSocketAddress& server_address,
      const ::quic::QuicSocketAddress& client_address,
      const std::string& hostname) override;

  void ComputeTlsSignature(
      const ::quic::QuicSocketAddress& server_address,
      const ::quic::QuicSocketAddress& client_address,
      const std::string& hostname,
      uint16_t signature_algorithm,
      quiche::QuicheStringPiece in,
      std::unique_ptr<SignatureCallback> callback) override;

  TicketCrypter* GetTicketCrypter() override;
  void SetTicketCrypter(std::unique_ptr<TicketCrypter> ticket_crypter);

 private:
  bool GetProofInner(
      const ::quic::QuicSocketAddress& server_ip,
      const std::string& hostname,
      const std::string& server_config,
      ::quic::QuicTransportVersion quic_version,
      quiche::QuicheStringPiece chlo_hash,
      ::quic::QuicReferenceCountedPointer<::quic::ProofSource::Chain>*
          out_chain,
      ::quic::QuicCryptoProof* proof);

  std::unique_ptr<crypto::RSAPrivateKey> private_key_;
  ::quic::QuicReferenceCountedPointer<::quic::ProofSource::Chain> chain_;
  std::unique_ptr<::quic::ProofSource::TicketCrypter> ticket_crypter_;

  DISALLOW_COPY_AND_ASSIGN(ProofSourceOwt);
};

}  // namespace quic
}  // namespace owt

#endif