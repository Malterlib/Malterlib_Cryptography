// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Cryptography_MessageAuthentication.h"

#include <Mib/Cryptography/BoringSSL>

#include <openssl/hmac.h>

namespace NMib::NCryptography
{
	using namespace NBoringSSL;

	struct CIncrementalHMAC::CInternal
	{
		CInternal(EDigestType _Digest, NContainer::CSecureByteVector const &_Key)
		{
			const EVP_MD *Md = fg_GetDigest(_Digest);
			umint const RequiredKeyLength = EVP_MD_size(Md);
			if (_Key.f_GetLen() < RequiredKeyLength)
				DMibErrorCryptography(NStr::fg_Format("HMAC key should be at least {} bytes", RequiredKeyLength));

			fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						ERR_clear_error();
						if (!(m_pHMACContext = HMAC_CTX_new()))
							DMibErrorCryptography(fg_GetExceptionStr("Failed to create HMAC context"));

						auto Cleanup = g_OnScopeExit / [&]
							{
								this->~CInternal();
							}
						;

						ERR_clear_error();
						if (HMAC_Init_ex(m_pHMACContext, _Key.f_GetArray(), _Key.f_GetLen(), Md, nullptr) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Failed to initialize HMAC context"));

						Cleanup.f_Clear();
					}
				)
			;
		}

		~CInternal()
		{
			HMAC_CTX_free(m_pHMACContext);
		}

		int32 f_GetHMACSize()
		{
			if (!m_pHMACContext)
				DMibErrorCryptography("No HMAC context. Please initialize before calling f_HMACSize.");

			return (int32)HMAC_size(m_pHMACContext);
		}

		void f_Update(uint8 const *_pSource, uint32 _SourceLen) const
		{
			if (!m_pHMACContext)
				DMibErrorCryptography("No HMAC context. Please initialize before calling f_Update.");

			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						ERR_clear_error();
						if (HMAC_Update(m_pHMACContext, _pSource, (int)_SourceLen) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Failed to update HMAC"));
					}
				)
			;
		}

		uint32 f_Finalize(uint8 *_pDest, uint32 _DestLen)
		{
			if (!m_pHMACContext)
				DMibErrorCryptography("No HMAC context. Please initialize before calling f_Finalize.");
			if (_DestLen < HMAC_size(m_pHMACContext))
				DMibErrorCryptography(NStr::fg_Format("Buffer is too short. The HMAC is {} bytes",  HMAC_size(m_pHMACContext)));

			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						unsigned int FinalizeLen = 0;
						ERR_clear_error();
						if (HMAC_Final(m_pHMACContext, _pDest, &FinalizeLen) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Failed to finalize HMAC data"));

						return FinalizeLen;
					}
				)
			;
		}

		HMAC_CTX *m_pHMACContext = nullptr;
	};

	CIncrementalHMAC::CIncrementalHMAC(EDigestType _Digest, NContainer::CSecureByteVector const &_Key)
		: mp_pInternal(fg_Construct(_Digest, _Key))
	{
	}

	CIncrementalHMAC::~CIncrementalHMAC()
	{
	}

	void CIncrementalHMAC::f_Update(uint8 const *_pSource, uint32 _SourceLen)
	{
		mp_pInternal->f_Update(_pSource, _SourceLen);
	}

	uint32 CIncrementalHMAC::f_Finalize(uint8 *_pDest, uint32 _DestLen)
	{
		return mp_pInternal->f_Finalize(_pDest, _DestLen);
	}

	uint32 CIncrementalHMAC::f_GetHMACSize() const
	{
		return mp_pInternal->f_GetHMACSize();
	}

	NCryptography::CHashDigest_SHA256 fg_MessageAuthenication_HMAC_SHA256(uint8 const *_pData, umint _DataLen, uint8 const *_pKey, umint _KeyLen)
	{
		NCryptography::CHashDigest_SHA256 Return;
		unsigned int Size = Return.mc_Size;
		if
			(
				!HMAC
				(
					EVP_sha256()
					, _pKey
					, _KeyLen
					, _pData
					, _DataLen
					, Return.f_GetData()
					, &Size
				)
			)
		{
			DMibErrorCryptography(fg_GetExceptionStr("Failed to run HMAC-SHA256"));
		}

		if (Size != Return.mc_Size)
			DMibErrorCryptography("Failed to run HMAC-SHA256: Unexpected digest size");

		return Return;
	}

	NCryptography::CHashDigest_SHA1 fg_MessageAuthenication_HMAC_SHA1(uint8 const *_pData, umint _DataLen, uint8 const *_pKey, umint _KeyLen)
	{
		NCryptography::CHashDigest_SHA1 Return;
		unsigned int Size = Return.mc_Size;
		if
			(
				!HMAC
				(
					EVP_sha1()
					, _pKey
					, _KeyLen
					, _pData
					, _DataLen
					, Return.f_GetData()
					, &Size
				)
			)
		{
			DMibErrorCryptography(fg_GetExceptionStr("Failed to run HMAC-SHA1"));
		}

		if (Size != Return.mc_Size)
			DMibErrorCryptography("Failed to run HMAC-SHA1: Unexpected digest size");

		return Return;
	}

	NCryptography::CHashDigest_SHA256 fg_MessageAuthenication_HMAC_SHA256(NContainer::CSecureByteVector const &_Data, NContainer::CSecureByteVector const &_Key)
	{
		return fg_MessageAuthenication_HMAC_SHA256(_Data.f_GetArray(), _Data.f_GetLen(), _Key.f_GetArray(), _Key.f_GetLen());
	}

	NCryptography::CHashDigest_SHA1 fg_MessageAuthenication_HMAC_SHA1(NContainer::CSecureByteVector const &_Data, NContainer::CSecureByteVector const &_Key)
	{
		return fg_MessageAuthenication_HMAC_SHA1(_Data.f_GetArray(), _Data.f_GetLen(), _Key.f_GetArray(), _Key.f_GetLen());
	}

	NCryptography::CHashDigest_SHA256 fg_MessageAuthenication_HMAC_SHA256(NContainer::CByteVector const &_Data, NContainer::CSecureByteVector const &_Key)
	{
		return fg_MessageAuthenication_HMAC_SHA256(_Data.f_GetArray(), _Data.f_GetLen(), _Key.f_GetArray(), _Key.f_GetLen());
	}

	NCryptography::CHashDigest_SHA1 fg_MessageAuthenication_HMAC_SHA1(NContainer::CByteVector const &_Data, NContainer::CSecureByteVector const &_Key)
	{
		return fg_MessageAuthenication_HMAC_SHA1(_Data.f_GetArray(), _Data.f_GetLen(), _Key.f_GetArray(), _Key.f_GetLen());
	}
}
