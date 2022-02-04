// Copyright (C) 2021-2022 The Xaya developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ETHUTILS_ECDSA_HPP
#define ETHUTILS_ECDSA_HPP

#include "address.hpp"

#include <memory>
#include <string>
#include <vector>

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

  class Key;

  ECDSA ();
  ~ECDSA ();

  ECDSA (const ECDSA&) = delete;
  void operator= (const ECDSA&) = delete;

  /**
   * Constructs and returns a secret key for this context from a string.
   * The string can either be a raw binary string with 32 bytes, or a
   * hex-encoded string with 0x prefix.
   */
  Key SecretKey (const std::string& inp) const;

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

  /**
   * Signs a message with the given key (using the legacy message encoding).
   * Returns the signature as hex string with 0x prefix.
   *
   * The key must be valid, or else the method CHECK fails.  Otherwise
   * it is guaranteed to succeed.
   */
  std::string SignMessage (const std::string& msg, const Key& key) const;

};

/**
 * A private key for signing ECDSA messages.
 */
class ECDSA::Key
{

private:

  /** The corresponding ECDSA context.  */
  const ECDSA* parent;

  /** The underlying 32-byte key or empty if the key is invalid.  */
  std::vector<unsigned char> data;

  /**
   * Constructs a key from given input.  The input should be either a raw
   * binary string of 32 bytes, or a hex-encoded string with 0x prefix.
   *
   * This method is called from ECDSA::SecretKey.
   */
  explicit Key (const ECDSA& p, const std::string& inp);

  friend class ECDSA;

public:

  /**
   * Constructs an invalid key (but it can be assigned to from other keys).
   */
  Key () = default;

  Key (const Key&) = default;
  Key (Key&&) = default;

  Key& operator= (const Key&) = default;
  Key& operator= (Key&&) = default;

  /**
   * Returns true if the key is valid.
   */
  inline operator
  bool () const
  {
    return !data.empty ();
  }

  /**
   * Returns the address corresponding to the key.
   */
  Address GetAddress () const;

};

} // namespace ethutils

#endif // ETHUTILS_ECDSA_HPP
