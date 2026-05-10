// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "Malterlib_Cryptography_KeyDerivation.h"

namespace NMib::NCryptography
{
	struct CScramSHA256Keys
	{
		NContainer::CSecureByteVector m_SaltedPassword;
		NContainer::CSecureByteVector m_ClientKey;
		CHashDigest_SHA256 m_StoredKey;
		NContainer::CSecureByteVector m_ServerKey;
	};

	CScramSHA256Keys fg_ScramSHA256DeriveKeys(NStr::CStrSecure const &_Password, NContainer::CByteVector const &_Salt, uint32 _Iterations);
	NContainer::CByteVector fg_ScramSHA256ClientProof(CScramSHA256Keys const &_Keys, NStr::CStr const &_AuthMessage);
	CHashDigest_SHA256 fg_ScramSHA256ServerSignature(CScramSHA256Keys const &_Keys, NStr::CStr const &_AuthMessage);
	bool fg_ScramSHA256VerifyServerSignature(CScramSHA256Keys const &_Keys, NStr::CStr const &_AuthMessage, uint8 const *_pSignature, umint _SignatureLen);
	bool fg_CryptographyConstantTimeEquals(uint8 const *_pLeft, uint8 const *_pRight, umint _Len);
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
