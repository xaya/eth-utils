// Copyright (C) 2021 The Xaya developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "keccak.hpp"

#include "keccak/sha3.h"

#include <glog/logging.h>

namespace ethutils
{

std::string
Keccak256 (const std::string& data)
{
  std::string res(32, '\0');
  const int ret = sha3_256 (reinterpret_cast<uint8_t*> (&res[0]), res.size (),
                            reinterpret_cast<const uint8_t*> (data.data ()),
                            data.size ());
  CHECK_EQ (ret, 0) << "Keccak implementation failed";
  return res;
}

} // namespace ethutils
