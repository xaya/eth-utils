// Copyright (C) 2021 The Xaya developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ecdsa.hpp"

#include "hexutils.hpp"

#include <gtest/gtest.h>

namespace ethutils
{
namespace
{

class EcdsaTests : public testing::Test
{

protected:

  ECDSA ec;

};

TEST_F (EcdsaTests, InvalidSignature)
{
  EXPECT_FALSE (ec.VerifyMessage ("", "aabbcc"));
  EXPECT_FALSE (ec.VerifyMessage ("", "0x123xyz"));
  EXPECT_FALSE (ec.VerifyMessage ("", "0x1234"));
  EXPECT_FALSE (ec.VerifyMessage ("", "0x"
      "08d7f4d7959eaa2abbd8cc6c0d7f57091d93eed4cdade4d0e763dc6be0d59aa7"
      "0accd2e4f72553763d6ebe867aceb5543c45c9a59194f1fb71c564356f5dd6f0"
      "1d"));
  EXPECT_FALSE (ec.VerifyMessage ("", "0x"
      "08d7f4d7959eaa2abbd8cc6c0d7f57091d93eed4cdade4d0e763dc6be0d59aa7"
      "0accd2e4f72553763d6ebe867aceb5543c45c9a59194f1fb71c564356f5dd6f0"
      "1a"));
}

TEST_F (EcdsaTests, RecoveredAddress)
{
  EXPECT_EQ (ec.VerifyMessage ("foobar", "0x"
      "08d7f4d7959eaa2abbd8cc6c0d7f57091d93eed4cdade4d0e763dc6be0d59aa7"
      "0accd2e4f72553763d6ebe867aceb5543c45c9a59194f1fb71c564356f5dd6f0"
      "1c"), Address ("0x14e663e1531e0f438840952d18720c74c28d4f20"));
}

} // anonymous namespace
} // namespace ethutils
