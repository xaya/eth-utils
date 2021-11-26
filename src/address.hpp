// Copyright (C) 2021 The Xaya developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ETHUTILS_ADDRESS_HPP
#define ETHUTILS_ADDRESS_HPP

#include <ostream>
#include <string>

namespace ethutils
{

/**
 * Representation of an Ethereum address, implementing the case checksum.
 */
class Address
{

private:

  /** The address in checksum format.  Empty string if it is invalid.  */
  std::string address;

public:

  /**
   * The default constructor generates an instance of an invalid
   * address (but it may be assigned to later on).
   */
  Address () = default;

  /**
   * Constructs an address based on the given input string.  The input
   * is verified and the address instance ends up invalid if it is neither
   * a full-lower-case address nor a valid checksummed one.
   */
  explicit Address (const std::string& addr);

  Address (const Address&) = default;
  Address (Address&&) = default;

  Address& operator= (const Address&) = default;
  Address& operator= (Address&) = default;

  /**
   * Returns true if the address is valid.
   */
  inline operator
  bool () const
  {
    return !address.empty ();
  }

  /**
   * Returns the address in checksummed form.  The address must be valid.
   */
  const std::string& GetChecksummed () const;

  /**
   * Returns the address in all lower-case form.  The address must be valid.
   */
  std::string GetLowerCase () const;

  /**
   * Compares two addresses for equality.  An invalid address compares inequal
   * to any other (including other invalid's).
   */
  friend bool operator== (const Address& a, const Address& b);

  friend bool
  operator!= (const Address& a, const Address& b)
  {
    return !(a == b);
  }

  friend std::ostream& operator<< (std::ostream& out, const Address& addr);

};

} // namespace ethutils

#endif // ETHUTILS_ADDRESS_HPP
