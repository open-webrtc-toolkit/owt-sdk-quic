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

#include "impl/proof_source_owt.h"
#include "base/files/file_util.h"
#include "base/strings/string_number_conversions.h"
#include "crypto/openssl_util.h"
#include "net/cert/x509_util.h"
#include "net/third_party/quiche/src/quic/core/crypto/crypto_protocol.h"
#include "third_party/boringssl/src/include/openssl/base.h"
#include "third_party/boringssl/src/include/openssl/pkcs8.h"
#include "third_party/boringssl/src/include/openssl/stack.h"

namespace owt {
namespace quic {

ProofSourceOwt::ProofSourceOwt() {}

ProofSourceOwt::~ProofSourceOwt() {}

bool ProofSourceOwt::Initialize(const base::FilePath& pfx_path,
                                const std::string& password) {
  crypto::EnsureOpenSSLInit();
  std::string pfx_data;
  if (!base::ReadFileToString(pfx_path, &pfx_data)) {
    DLOG(FATAL) << "Unable to read pfx file.";
    return false;
  }
  EVP_PKEY* key = nullptr;
  bssl::UniquePtr<STACK_OF(X509)> certs(sk_X509_new_null());
  CBS pkcs12;
  CBS_init(&pkcs12, reinterpret_cast<const uint8_t*>(pfx_data.c_str()),
           pfx_data.size());
  if (PKCS12_get_key_and_certs(&key, certs.get(), &pkcs12, password.c_str()) ==
      0) {
    return false;
  }
  std::vector<std::string> certs_string;
  for (X509* cert : certs.get()) {
    int len(0);
    unsigned char* buffer(nullptr);
    len = i2d_X509(cert, &buffer);
    if (len < 0) {
      LOG(ERROR) << "Failed to get X509 certificate.";
      return false;
    }
    bssl::UniquePtr<CRYPTO_BUFFER> crypto_buffer =
        net::x509_util::CreateCryptoBuffer(buffer, len);
    certs_string.emplace_back(
        net::x509_util::CryptoBufferAsStringPiece(crypto_buffer.get()));
  }
  chain_ = new ::quic::ProofSource::Chain(certs_string);
  private_key_ = crypto::RSAPrivateKey::CreateFromKey(key);
  return true;
}

::quic::ProofSource::TicketCrypter* ProofSourceOwt::GetTicketCrypter() {
  return ticket_crypter_.get();
}

void ProofSourceOwt::SetTicketCrypter(
    std::unique_ptr<::quic::ProofSource::TicketCrypter> ticket_crypter) {
  ticket_crypter_ = std::move(ticket_crypter);
}

bool ProofSourceOwt::GetProofInner(
    const ::quic::QuicSocketAddress& server_addr,
    const std::string& hostname,
    const std::string& server_config,
    ::quic::QuicTransportVersion quic_version,
    absl::string_view chlo_hash,
    ::quic::QuicReferenceCountedPointer<::quic::ProofSource::Chain>* out_chain,
    ::quic::QuicCryptoProof* proof) {
  // This function is copied from `ProofSourceChromium`, but `leaf_cert_scts` is
  // not set.
  DCHECK(proof != nullptr);
  DCHECK(private_key_.get()) << " this: " << this;

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  bssl::ScopedEVP_MD_CTX sign_context;
  EVP_PKEY_CTX* pkey_ctx;

  uint32_t len_tmp = chlo_hash.length();
  if (!EVP_DigestSignInit(sign_context.get(), &pkey_ctx, EVP_sha256(), nullptr,
                          private_key_->key()) ||
      !EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) ||
      !EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) ||
      !EVP_DigestSignUpdate(
          sign_context.get(),
          reinterpret_cast<const uint8_t*>(::quic::kProofSignatureLabel),
          sizeof(::quic::kProofSignatureLabel)) ||
      !EVP_DigestSignUpdate(sign_context.get(),
                            reinterpret_cast<const uint8_t*>(&len_tmp),
                            sizeof(len_tmp)) ||
      !EVP_DigestSignUpdate(sign_context.get(),
                            reinterpret_cast<const uint8_t*>(chlo_hash.data()),
                            len_tmp) ||
      !EVP_DigestSignUpdate(
          sign_context.get(),
          reinterpret_cast<const uint8_t*>(server_config.data()),
          server_config.size())) {
    return false;
  }
  // Determine the maximum length of the signature.
  size_t len = 0;
  if (!EVP_DigestSignFinal(sign_context.get(), nullptr, &len)) {
    return false;
  }
  std::vector<uint8_t> signature(len);
  // Sign it.
  if (!EVP_DigestSignFinal(sign_context.get(), signature.data(), &len)) {
    return false;
  }
  signature.resize(len);
  proof->signature.assign(reinterpret_cast<const char*>(signature.data()),
                          signature.size());
  *out_chain = chain_;
  VLOG(1) << "signature: "
          << base::HexEncode(proof->signature.data(), proof->signature.size());
  return true;
}

void ProofSourceOwt::GetProof(const ::quic::QuicSocketAddress& server_address,
                              const ::quic::QuicSocketAddress& client_address,
                              const std::string& hostname,
                              const std::string& server_config,
                              ::quic::QuicTransportVersion quic_version,
                              absl::string_view chlo_hash,
                              std::unique_ptr<Callback> callback) {
  // As a transitional implementation, just call the synchronous version of
  // GetProof, then invoke the callback with the results and destroy it.
  ::quic::QuicReferenceCountedPointer<::quic::ProofSource::Chain> chain;
  std::string signature;
  std::string leaf_cert_sct;
  ::quic::QuicCryptoProof out_proof;

  const bool ok = GetProofInner(server_address, hostname, server_config,
                                quic_version, chlo_hash, &chain, &out_proof);
  callback->Run(ok, chain, out_proof, nullptr /* details */);
}

::quic::QuicReferenceCountedPointer<::quic::ProofSource::Chain>
ProofSourceOwt::GetCertChain(const ::quic::QuicSocketAddress& server_address,
                             const ::quic::QuicSocketAddress& client_address,
                             const std::string& hostname) {
  return chain_;
}

void ProofSourceOwt::ComputeTlsSignature(
    const ::quic::QuicSocketAddress& server_address,
    const ::quic::QuicSocketAddress& client_address,
    const std::string& hostname,
    uint16_t signature_algorithm,
    absl::string_view in,
    std::unique_ptr<SignatureCallback> callback) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  bssl::ScopedEVP_MD_CTX sign_context;
  EVP_PKEY_CTX* pkey_ctx;

  size_t siglen;
  std::string sig;
  if (!EVP_DigestSignInit(sign_context.get(), &pkey_ctx, EVP_sha256(), nullptr,
                          private_key_->key()) ||
      !EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) ||
      !EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) ||
      !EVP_DigestSignUpdate(sign_context.get(),
                            reinterpret_cast<const uint8_t*>(in.data()),
                            in.size()) ||
      !EVP_DigestSignFinal(sign_context.get(), nullptr, &siglen)) {
    callback->Run(false, sig, nullptr);
    return;
  }
  sig.resize(siglen);
  if (!EVP_DigestSignFinal(
          sign_context.get(),
          reinterpret_cast<uint8_t*>(const_cast<char*>(sig.data())), &siglen)) {
    callback->Run(false, sig, nullptr);
    return;
  }
  sig.resize(siglen);

  callback->Run(true, sig, nullptr);
}

}  // namespace quic
}  // namespace owt
