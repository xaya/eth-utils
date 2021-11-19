// Copyright (C) 2021 The Xaya developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ETHUTILS_HEXUTILS_HPP
#define ETHUTILS_HEXUTILS_HPP

#include <string>

namespace ethutils
{

/**
 * Converts a binary string to hex.
 */
std::string Hexlify (const std::string& bin);

/**
 * Converts a hex string into a binary string.  Returns false if the input
 * string is not valid hex.
 */
bool Unhexlify (const std::string& hex, std::string& bin);

} // namespace ethutils

#endif // ETHUTILS_HEXUTILS_HPP
