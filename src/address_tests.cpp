// Copyright (C) 2021 The Xaya developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "address.hpp"

#include <gtest/gtest.h>

namespace ethutils
{
namespace
{

using AddressTests = testing::Test;

TEST_F (AddressTests, InvalidFormat)
{
  EXPECT_FALSE (Address ("foo"));
  EXPECT_FALSE (Address ("0xaab"));
  EXPECT_FALSE (Address ("0xinvalidd"));
  EXPECT_FALSE (Address ("0x1234"));
}

TEST_F (AddressTests, InvalidChecksum)
{
  EXPECT_FALSE (Address ("0x5aAeb6053f3E94C9b9A09f33669435E7Ef1BeAed"));
  EXPECT_FALSE (Address ("0xFB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"));
  EXPECT_FALSE (Address ("0xdbF03B407d01E7cD3CBea99509d93f8DDDC8C6FB"));
  EXPECT_FALSE (Address ("0xD1220A0cf47c7B9Be5A2E6BA89F429762e7b9aDb"));
}

TEST_F (AddressTests, ValidLowerCase)
{
  EXPECT_TRUE (Address ("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"));
}

TEST_F (AddressTests, ValidChecksums)
{
  EXPECT_TRUE (Address ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"));
  EXPECT_TRUE (Address ("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"));
  EXPECT_TRUE (Address ("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"));
  EXPECT_TRUE (Address ("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"));
}

TEST_F (AddressTests, ReturnInChosenFormat)
{
  const Address addr("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
  ASSERT_TRUE (addr);
  EXPECT_EQ (addr.GetLowerCase (),
             "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
  EXPECT_EQ (addr.GetChecksummed (),
             "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
}

TEST_F (AddressTests, Roundtrip)
{
  const Address addr("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
  ASSERT_TRUE (addr);
  EXPECT_EQ (addr, Address (addr.GetLowerCase ()));
  EXPECT_EQ (addr, Address (addr.GetChecksummed ()));
}

} // anonymous namespace
} // namespace ethutils
