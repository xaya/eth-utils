// Copyright (C) 2021 The Xaya developers
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
          **ctx, &sig,
          reinterpret_cast<const unsigned char*> (sgnBin.data ()),
          recoveryId))
    {
      LOG (WARNING) << "Failed to parse recoverable signature";
      return Address ();
    }

  secp256k1_pubkey pubkey;
  if (!secp256k1_ecdsa_recover (
      **ctx, &pubkey, &sig,
      reinterpret_cast<const unsigned char*> (msgHash.data ())))
    {
      LOG (WARNING) << "Failed to recover public key from signature";
      return Address ();
    }

  /* Format the recovered pubkey as uncompressed byte array.  This will yield
     65 bytes, with the first being 0x04 to denote it is uncompressed, and the
     following 64 bytes being the actual curve point.  */
  std::string pubkeyBin(65, '\0');
  size_t pubkeyBinLen = pubkeyBin.size ();
  CHECK (secp256k1_ec_pubkey_serialize (
            **ctx,
            reinterpret_cast<unsigned char*> (&pubkeyBin[0]), &pubkeyBinLen,
            &pubkey, SECP256K1_EC_UNCOMPRESSED))
      << "Serialising the pubkey failed";
  CHECK_EQ (pubkeyBinLen, 65) << "Unexpected serialised pubkey length returned";
  CHECK_EQ (pubkeyBin[0], '\x04')
      << "Unexpected first byte in serialised uncompressed pubkey";

  /* Generate the Ethereum address from the pubkey.  */
  const std::string pubkeyHash = Keccak256 (pubkeyBin.substr (1));
  CHECK_EQ (pubkeyHash.size (), 32);
  return Address ("0x" + Hexlify (pubkeyHash.substr (12)));
}

} // namespace ethutils
