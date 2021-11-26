// Copyright (C) 2021 The Xaya developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "address.hpp"

#include "hexutils.hpp"
#include "keccak.hpp"

#include <glog/logging.h>

namespace ethutils
{

namespace
{

/**
 * Lower-cases a hex string.
 */
std::string
ToLower (const std::string& str)
{
  std::string res;
  for (const char c : str)
    {
      /* Note that this also handles the "0x" prefix correctly.  */
      res.push_back (std::tolower (c));
    }
  return res;
}

} // anonymous namespace

Address::Address (const std::string& addr)
{
  std::string lower = ToLower (addr);
  if (lower.substr (0, 2) != "0x")
    {
      LOG (WARNING) << "Address is missing 0x prefix: " << addr;
      return;
    }
  lower = lower.substr (2);

  std::string bytes;
  if (!Unhexlify (lower, bytes))
    {
      LOG (WARNING) << "Address is not valid hex: " << addr;
      return;
    }
  if (bytes.size () != 20)
    {
      LOG (WARNING) << "Address has invalid size: " << addr;
      return;
    }

  const std::string hash = Keccak256 (lower);
  CHECK_EQ (hash.size (), 32);

  std::string res("0x");
  for (unsigned i = 0; i + 2 < addr.size (); ++i)
    {
      uint8_t byte = hash[i / 2];
      if (i % 2 == 0)
        byte >>= 4;
      const bool wantUpper = (byte & 0x8);

      const char c = addr[i + 2];
      if (wantUpper)
        res.push_back (std::toupper (c));
      else
        res.push_back (std::tolower (c));
    }

  /* The address is valid if it is either all lower-case or matches
     the computed checksummed version.  */
  if (addr != res && addr != "0x" + lower)
    {
      LOG (WARNING) << "Address is invalid: " << addr;
      return;
    }

  address = res;
}

const std::string&
Address::GetChecksummed () const
{
  CHECK (*this) << "Address is not valid";
  return address;
}

std::string
Address::GetLowerCase () const
{
  return ToLower (GetChecksummed ());
}

bool
operator== (const Address& a, const Address& b)
{
  if (!a || !b)
    return false;
  return a.address == b.address;
}

std::ostream&
operator<< (std::ostream& out, const Address& addr)
{
  out << (addr ? addr.GetChecksummed () : "<invalid address>");
  return out;
}

} // namespace ethutils
