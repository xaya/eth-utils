// Copyright (C) 2021 The Xaya developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ETHUTILS_KECCAK_HPP
#define ETHUTILS_KECCAK_HPP

#include <string>

namespace ethutils
{

/**
 * Computes the Keccak-256 hash of the given binary data.  The result
 * will be a binary string of length 32 bytes.  This is the hash function
 * used by Ethereum.
 */
std::string Keccak256 (const std::string& data);

} // namespace ethutils

#endif // ETHUTILS_KECCAK_HPP
