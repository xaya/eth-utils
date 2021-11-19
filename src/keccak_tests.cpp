// Copyright (C) 2021 The Xaya developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "keccak.hpp"

#include "hexutils.hpp"

#include <gtest/gtest.h>

namespace ethutils
{
namespace
{

class KeccakTests : public testing::Test
{

protected:

  /**
   * Computes the Keccak-256 hash of the given binary string and returns
   * the result as hex string.
   */
  static std::string
  HexKeccak (const std::string& data)
  {
    return "0x" + Hexlify (Keccak256 (data));
  }

};

TEST_F (KeccakTests, Works)
{
  EXPECT_EQ (HexKeccak (""),
      "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  EXPECT_EQ (HexKeccak (std::string ("\0", 1)),
      "0xbc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a");
  EXPECT_EQ (HexKeccak ("hello, world"),
      "0x29bf7021020ea89dbd91ef52022b5a654b55ed418c9e7aba71ef3b43a51669f2");
  EXPECT_EQ (HexKeccak (std::string (1'024, 'x')),
      "0x36782afd471b2fcfd6b549502cf385072800fa99bdef3ebb9d525bd010084d17");
}

} // anonymous namespace
} // namespace ethutils
