#pragma once

#include "Malterlib_Cryptography_Exception.h"

namespace NMib::NCryptography
{
	enum EDigestType
	{
		EDigestType_None
		, EDigestType_Automatic
		, EDigestType_SHA512
		, EDigestType_SHA384
		, EDigestType_SHA256
		, EDigestType_SHA224
		, EDigestType_SHA1		// Be careful, only to be used for compatibility with legacy systems (borken hash)
		, EDigestType_MD5		// Be careful, only to be used for compatibility with legacy systems (borken hash)
		, EDigestType_MD4		// Be careful, only to be used for compatibility with legacy systems (borken hash)
	};

	class CIncrementalHMAC
	{
	public:
		CIncrementalHMAC(EDigestType _Digest, NContainer::CSecureByteVector const &_Key);
		~CIncrementalHMAC();

		void f_Update(uint8 const *_pSource, uint32 _SourceLen);
		uint32 f_Finalize(uint8 *_pDest, uint32 _DestLen);
		uint32 f_GetHMACSize() const;

	private:
		struct CInternal;
		NStorage::TCUniquePointer<CInternal> mp_pInternal;
	};

	NCryptography::CHashDigest_SHA256 fg_MessageAuthenication_HMAC_SHA256(uint8 const *_pData, mint _DataLen, uint8 const *_pKey, mint _KeyLen);
	NCryptography::CHashDigest_SHA1 fg_MessageAuthenication_HMAC_SHA1(uint8 const *_pData, mint _DataLen, uint8 const *_pKey, mint _KeyLen);
	NCryptography::CHashDigest_SHA256 fg_MessageAuthenication_HMAC_SHA256(NContainer::CSecureByteVector const &_Data, NContainer::CSecureByteVector const &_Key);
	NCryptography::CHashDigest_SHA1 fg_MessageAuthenication_HMAC_SHA1(NContainer::CSecureByteVector const &_Data, NContainer::CSecureByteVector const &_Key);
	NCryptography::CHashDigest_SHA256 fg_MessageAuthenication_HMAC_SHA256(NContainer::CByteVector const &_Data, NContainer::CSecureByteVector const &_Key);
	NCryptography::CHashDigest_SHA1 fg_MessageAuthenication_HMAC_SHA1(NContainer::CByteVector const &_Data, NContainer::CSecureByteVector const &_Key);
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
