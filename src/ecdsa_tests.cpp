// Copyright (C) 2021 The Xaya developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ecdsa.hpp"

#include "hexutils.hpp"

#include <glog/logging.h>
#include <gtest/gtest.h>

namespace ethutils
{
namespace
{

class EcdsaTests : public testing::Test
{

protected:

  /** Some secret key.  */
  static const std::string SECRET;
  /** The associated address.  */
  static const Address ADDRESS;

  ECDSA ec;

  EcdsaTests ()
  {
    CHECK (ADDRESS);
  }

};

const std::string EcdsaTests::SECRET
    = "0x918fb30e03abd86ddbfcffb1ec3ea86607d56f307e2ffac71ffb41cbc813d093";
const Address EcdsaTests::ADDRESS("0x57a4840a6f1C5C3CeA6EF06F09e5AC8bEC65FC69");

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

TEST_F (EcdsaTests, SecretKeys)
{
  EXPECT_FALSE (ec.SecretKey ("abc"));
  EXPECT_FALSE (ec.SecretKey (std::string ('\0', 32)));
  EXPECT_FALSE (ec.SecretKey ("0x" + std::string ('f', 64)));

  const auto k1 = ec.SecretKey (SECRET);
  ASSERT_TRUE (k1);
  EXPECT_EQ (k1.GetAddress (), ADDRESS);

  std::string bin;
  ASSERT_TRUE (Unhexlify (SECRET.substr (2), bin));
  const auto k2 = ec.SecretKey (bin);
  ASSERT_TRUE (k2);
  EXPECT_EQ (k2.GetAddress (), ADDRESS);
}

} // anonymous namespace
} // namespace ethutils
