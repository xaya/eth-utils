// Copyright (C) 2021-2022 The Xaya developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ecdsa.hpp"

#include "hexutils.hpp"
#include "keccak.hpp"

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <glog/logging.h>

#include <sstream>

namespace ethutils
{

namespace
{

/**
 * Returns the bytes of a string as unsigned char (as used for libsecp256k1).
 */
const unsigned char*
UChar (const std::string& str)
{
  return reinterpret_cast<const unsigned char*> (str.data ());
}

/**
 * Mutable variant of UChar.
 */
unsigned char*
UChar (std::string& str)
{
  return reinterpret_cast<unsigned char*> (&str[0]);
}

/**
 * Converts a secp256k1 pubkey into an address.
 */
Address
PubkeyToAddress (const secp256k1_context* ctx, const secp256k1_pubkey& pubkey)
{
  std::string pubkeyBin(65, '\0');
  size_t pubkeyBinLen = pubkeyBin.size ();
  CHECK (secp256k1_ec_pubkey_serialize (
            ctx, UChar (pubkeyBin), &pubkeyBinLen,
            &pubkey, SECP256K1_EC_UNCOMPRESSED))
      << "Serialising the pubkey failed";
  CHECK_EQ (pubkeyBinLen, 65) << "Unexpected serialised pubkey length returned";
  CHECK_EQ (pubkeyBin[0], '\x04')
      << "Unexpected first byte in serialised uncompressed pubkey";

  const std::string pubkeyHash = Keccak256 (pubkeyBin.substr (1));
  CHECK_EQ (pubkeyHash.size (), 32);
  return Address ("0x" + Hexlify (pubkeyHash.substr (12)));
}

} // anonymous namespace

/* ************************************************************************** */

/**
 * Wrapper class around the libsecp256k1 context, so we can hide the library
 * as implementation detail.
 */
class ECDSA::Context
{

private:

  /** The actual libsecp256k1 context.  */
  secp256k1_context* ctx;

public:

  Context ()
  {
    ctx = secp256k1_context_create (SECP256K1_CONTEXT_VERIFY);
  }

  ~Context ()
  {
    secp256k1_context_destroy (ctx);
  }

  const secp256k1_context*
  operator* () const
  {
    return ctx;
  }

};

ECDSA::ECDSA ()
{
  ctx = std::make_unique<Context> ();
}

ECDSA::~ECDSA () = default;

ECDSA::Key
ECDSA::SecretKey (const std::string& inp) const
{
  return Key (*this, inp);
}

/* ************************************************************************** */

ECDSA::Key::Key (const ECDSA& p, const std::string& inp)
  : parent(&p)
{
  std::string binKey;

  if (inp.size () == 32)
    binKey = inp;
  else if (inp.size () == 2 + 2 * 32)
    {
      if (inp.substr (0, 2) != "0x")
        {
          LOG (WARNING) << "Secret key is missing 0x prefix";
          return;
        }

      if (!Unhexlify (inp.substr (2), binKey))
        {
          LOG (WARNING) << "Secret key is invalid hex";
          return;
        }
    }
  else
    {
      LOG (WARNING) << "Secret key has invalid length " << inp.size ();
      return;
    }

  const unsigned char* buf = UChar (binKey);
  std::vector<unsigned char> bytes(buf, buf + binKey.size ());
  CHECK_EQ (bytes.size (), 32);

  if (secp256k1_ec_seckey_verify (**parent->ctx, bytes.data ()))
    data = std::move (bytes);
  else
    LOG (WARNING) << "Secret key is invalid";
}

Address
ECDSA::Key::GetAddress () const
{
  CHECK (*this) << "Key is not valid";

  /* Note that the secret key is validated by libsecp256k1 whenever
     the instance is initialised already.  So at this point, it is always
     valid and thus the pubkey conversion should never fail.  */
  secp256k1_pubkey pubkey;
  CHECK (secp256k1_ec_pubkey_create (**parent->ctx, &pubkey, data.data ()))
      << "Conversion of secret to public key failed";

  return PubkeyToAddress (**parent->ctx, pubkey);
}

/* ************************************************************************** */

Address
ECDSA::VerifyMessage (const std::string& msg, const std::string& sgnHex) const
{
  std::ostringstream msgToHash;
  msgToHash << '\x19' << "Ethereum Signed Message:\n"
            << msg.size () << msg;
  const std::string msgHash = Keccak256 (msgToHash.str ());
  CHECK_EQ (msgHash.size (), 32);

  /* Parse the Ethereum signature into the 64-byte curve point and the
     recovery ID.  The recovery ID is the 65th byte, and it is 27 or 28
     while libsecp256k1 expects it as 0 or 1.  */
  if (sgnHex.substr (0, 2) != "0x")
    {
      LOG (WARNING) << "Signature string is missing 0x prefix";
      return Address ();
    }
  std::string sgnBin;
  if (!Unhexlify (sgnHex.substr (2), sgnBin))
    {
      LOG (WARNING) << "Signature string is invalid hex";
      return Address ();
    }
  if (sgnBin.size () != 65)
    {
      LOG (WARNING) << "Signature has wrong size";
      return Address ();
    }
  int recoveryId = static_cast<int> (sgnBin[64]);
  if (recoveryId != 27 && recoveryId != 28)
    {
      LOG (WARNING) << "Signature v has unexpected value";
      return Address ();
    }
  recoveryId -= 27;
  CHECK (recoveryId >= 0 && recoveryId <= 1);

  secp256k1_ecdsa_recoverable_signature sig;
  if (!secp256k1_ecdsa_recoverable_signature_parse_compact (
          **ctx, &sig, UChar (sgnBin), recoveryId))
    {
      LOG (WARNING) << "Failed to parse recoverable signature";
      return Address ();
    }

  secp256k1_pubkey pubkey;
  if (!secp256k1_ecdsa_recover (
      **ctx, &pubkey, &sig, UChar (msgHash)))
    {
      LOG (WARNING) << "Failed to recover public key from signature";
      return Address ();
    }

  return PubkeyToAddress (**ctx, pubkey);
}

/* ************************************************************************** */

} // namespace ethutils
