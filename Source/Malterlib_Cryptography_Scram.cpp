// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Cryptography_Scram.h"

#include <Mib/Cryptography/BoringSSL>

#include <openssl/crypto.h>

namespace NMib::NCryptography
{
	namespace
	{
		NContainer::CByteVector fg_ByteVectorFromString(NStr::CStr const &_String)
		{
			NContainer::CByteVector Data;
			Data.f_Insert((uint8 const *)_String.f_GetStr(), _String.f_GetLen());
			return Data;
		}

		NContainer::CSecureByteVector fg_SecureVectorFromDigest(CHashDigest_SHA256 const &_Digest)
		{
			NContainer::CSecureByteVector Data;
			Data.f_Insert(_Digest.f_GetData(), _Digest.mc_Size);
			return Data;
		}
	}

	bool fg_CryptographyConstantTimeEquals(uint8 const *_pLeft, uint8 const *_pRight, umint _Len)
	{
		return CRYPTO_memcmp(_pLeft, _pRight, _Len) == 0;
	}

	CScramSHA256Keys fg_ScramSHA256DeriveKeys(NStr::CStrSecure const &_Password, NContainer::CByteVector const &_Salt, uint32 _Iterations)
	{
		NContainer::CSecureByteVector SecureSalt;
		SecureSalt.f_Insert(_Salt.f_GetArray(), _Salt.f_GetLen());

		CScramSHA256Keys Keys;
		Keys.m_SaltedPassword = fg_DeriveKey
			(
				_Password
				, SecureSalt
				, CKeyDerivationSettings_PKCS5_PBKDF2_HMAC
				{
					.m_Digest = EDigestType_SHA256
					, .m_Rounds = _Iterations
				}
				, CHash_SHA256::mc_DigestSize
			)
		;

		CHashDigest_SHA256 ClientKeyDigest = fg_MessageAuthenication_HMAC_SHA256(fg_ByteVectorFromString("Client Key"), Keys.m_SaltedPassword);
		Keys.m_ClientKey = fg_SecureVectorFromDigest(ClientKeyDigest);
		Keys.m_StoredKey = CHash_SHA256::fs_DigestFromData(Keys.m_ClientKey);

		CHashDigest_SHA256 ServerKeyDigest = fg_MessageAuthenication_HMAC_SHA256(fg_ByteVectorFromString("Server Key"), Keys.m_SaltedPassword);
		Keys.m_ServerKey = fg_SecureVectorFromDigest(ServerKeyDigest);
		return Keys;
	}

	NContainer::CByteVector fg_ScramSHA256ClientProof(CScramSHA256Keys const &_Keys, NStr::CStr const &_AuthMessage)
	{
		NContainer::CSecureByteVector StoredKey = fg_SecureVectorFromDigest(_Keys.m_StoredKey);
		CHashDigest_SHA256 ClientSignature = fg_MessageAuthenication_HMAC_SHA256(fg_ByteVectorFromString(_AuthMessage), StoredKey);

		NContainer::CByteVector Proof;
		Proof.f_SetLen(_Keys.m_ClientKey.f_GetLen());
		for (umint i = 0; i < Proof.f_GetLen(); ++i)
			Proof[i] = _Keys.m_ClientKey[i] ^ ClientSignature.f_GetData()[i];
		return Proof;
	}

	CHashDigest_SHA256 fg_ScramSHA256ServerSignature(CScramSHA256Keys const &_Keys, NStr::CStr const &_AuthMessage)
	{
		return fg_MessageAuthenication_HMAC_SHA256(fg_ByteVectorFromString(_AuthMessage), _Keys.m_ServerKey);
	}

	bool fg_ScramSHA256VerifyServerSignature(CScramSHA256Keys const &_Keys, NStr::CStr const &_AuthMessage, uint8 const *_pSignature, umint _SignatureLen)
	{
		CHashDigest_SHA256 Signature = fg_ScramSHA256ServerSignature(_Keys, _AuthMessage);
		if (_SignatureLen != Signature.mc_Size)
			return false;
		return fg_CryptographyConstantTimeEquals(Signature.f_GetData(), _pSignature, Signature.mc_Size);
	}
}
