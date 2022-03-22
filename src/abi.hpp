// Copyright (C) 2021-2022 The Xaya developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ETHUTILS_ABI_HPP
#define ETHUTILS_ABI_HPP

#include <cstdint>
#include <sstream>
#include <string>

namespace ethutils
{

/**
 * Helper class for decoding data from an ABI-encoded hex string.
 */
class AbiDecoder
{

private:

  /** The input data being read (as hex string).  */
  std::string data;

  /** The stream of input data.  */
  std::istringstream in;

  /* The data string passed may not end exactly at the end of this decoder's
     data (for instance, when ReadDynamic is used to construct it).  We keep
     track of the actual data accessed (both in the heads and tail parts),
     so that after reading all, we can then extract the exact data,
     as that can be useful.  */

  /** End pointer in the heads part (first byte not yet accessed).  */
  size_t headEnd = 0;

  /** End pointer in the tail part.  */
  size_t tailEnd = 0;

  /**
   * If this is based on the tail data of another decoder (using ReadDyanmic),
   * this points to the parent decoder.  In this situation, the tailEnd
   * of the parent decoder will be updated when this instance is destructed.
   */
  AbiDecoder* parent;

  /**
   * If we have a parent, the offset into the parent's data for where our
   * own data starts.
   */
  size_t parentOffset;

  /**
   * Reads the given number of bytes as hex characters (i.e. 2n characters)
   * from the input stream and returns them as hex string.
   */
  std::string ReadBytes (size_t len);

public:

  explicit AbiDecoder (const std::string& str);

  /**
   * Constructs a decoder based on the data of the given other decoder,
   * starting at a given index (by bytes, not hex characters).  If this
   * method is used, then the end-mark of the underlying decoder will be
   * updated based on data read from here once this decoder is destructed.
   */
  explicit AbiDecoder (AbiDecoder& other, size_t start);

  ~AbiDecoder ();

  AbiDecoder (AbiDecoder&) = delete;
  void operator= (AbiDecoder&) = delete;

  AbiDecoder (AbiDecoder&&) = default;
  AbiDecoder& operator= (AbiDecoder&&) = default;

  /**
   * Reads a blob of fixed bit size (e.g. uint256 or address/uint160).
   * It is returned as hex string with 0x prefix again.
   */
  std::string ReadUint (int bits);

  /**
   * Reads a generic dynamic piece of data.  This returns a new AbiDecoder
   * instance that is based on the tail data.
   */
  AbiDecoder ReadDynamic ();

  /**
   * Reads in a string value into a (potentially binary) string.
   */
  std::string ReadString ();

  /**
   * Reads a dynamic array.  It sets the length in the output argument,
   * and returns a new decoder that will return the elements one by one.
   */
  AbiDecoder ReadArray (size_t& len);

  /**
   * Returns the full data (as hex string) actually read so far from
   * this decoder, based on our tracked end positions.
   */
  std::string GetAllDataRead () const;

  /**
   * Parses a string (hex or decimal) as integer, verifying that
   * it fits into int64_t.
   */
  static int64_t ParseInt (const std::string& str);

};

/**
 * Helper class for encoding data into an ABI blob (hex string).
 */
class AbiEncoder
{

private:

  /**
   * The expected number of words (32-byte groups) in the heads part.
   * For simplicity, this must be set beforehand when constructing the
   * encoder, is used for constructing the tail references for dynamic
   * types, and verified at the end against the actual head generated.
   */
  const unsigned headWords;

  /** The stream of head data being written.  */
  std::ostringstream head;

  /** The stream of tail data being written.  */
  std::ostringstream tail;

public:

  /**
   * Constructs a new AbiEncoder instance that is supposed to write the
   * given number of words on the head part.
   */
  explicit AbiEncoder (unsigned w)
    : headWords(w)
  {}

  /**
   * Writes a word of uint data, which will be padded to 32 bytes with
   * zeros as needed.
   */
  void WriteWord (const std::string& data);

  /**
   * Writes the given data as a dynamic "bytes" instance.
   */
  void WriteBytes (const std::string& data);

  /**
   * Constructs the final string.  Exactly the right number of head words
   * must have been constructed.
   */
  std::string Finalise () const;

  /**
   * Concatenates two 0x-prefixed hex strings.
   */
  static std::string ConcatHex (const std::string& a, const std::string& b);

  /**
   * Formats a given integer as hex literal suitable to be written
   * with WriteWord (for instance).
   */
  static std::string FormatInt (uint64_t val);

};

} // namespace ethutils

#endif // ETHUTILS_ABI_HPP
