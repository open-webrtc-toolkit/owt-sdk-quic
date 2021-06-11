/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "owt/web_transport/sdk/impl/proof_source_owt.h"
#include "base/files/file_path.h"
#include "base/path_service.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace owt {
namespace quic {
namespace test {

const base::FilePath::CharType kCertificatePath[] =
    FILE_PATH_LITERAL("owt/web_transport/sdk/resources/ssl/certificates");

TEST(ProofSourceOwtTest, InitializeProofSourceWithValidPassword) {
  owt::quic::ProofSourceOwt proof_source;
  base::FilePath src_root;
  base::PathService::Get(base::DIR_SOURCE_ROOT, &src_root);
  base::FilePath pfx_path(src_root.Append(kCertificatePath)
                              .AppendASCII("proof_source_pkcs12_test.pfx"));
  EXPECT_TRUE(proof_source.Initialize(pfx_path, "password"));
  EXPECT_FALSE(proof_source.Initialize(pfx_path, "wrong_password"));
}

}  // namespace test
}  // namespace quic
}  // namespace owt