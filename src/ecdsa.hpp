// Copyright (C) 2021 The Xaya developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ETHUTILS_ECDSA_HPP
#define ETHUTILS_ECDSA_HPP

#include "address.hpp"

#include <memory>
#include <string>

namespace ethutils
{

/**
 * Class for performing ECDSA operations (e.g. verifying signatures)
 * on the secp256k1 curve that Ethereum uses.  The instance encapsulates
 * some precomputation tables (a context from the underlying libsecp256k1
 * library), which is more efficient to keep around than recreate on
 * every operation.
 */
class ECDSA
{

private:

  class Context;

  /** Context of precomputed state.  */
  std::unique_ptr<Context> ctx;

public:

  ECDSA ();
  ~ECDSA ();

  ECDSA (const ECDSA&) = delete;
  void operator= (const ECDSA&) = delete;

  /**
   * Verifies an Ethereum signature made on a message.  Returns the
   * recovered address that signed or an invalid address
   * if the signature is invalid in general.
   *
   * The message is a general byte string, and the signature is given as
   * 65-byte hex string with 0x prefix.
   */
   Address VerifyMessage (const std::string& msg,
                          const std::string& sgnHex) const;

};

} // namespace ethutils

#endif // ETHUTILS_ECDSA_HPP
