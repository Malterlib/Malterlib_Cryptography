#pragma once

#include "Malterlib_Cryptography_MessageAuthentication.h"
#include "Malterlib_Cryptography_Exception.h"

#include <Mib/Storage/Variant>

namespace NMib::NCryptography
{
	enum EPublicKeyType
	{
		EPublicKeyType_RSA
		, EPublicKeyType_EC_secp256r1
		, EPublicKeyType_EC_secp384r1
		, EPublicKeyType_EC_secp521r1
		, EPublicKeyType_EC_X25519
	};

	struct CPublicKeySettings_RSA
	{
		CPublicKeySettings_RSA() = default;
		CPublicKeySettings_RSA(uint32 _KeyLength)
			: m_KeyLength(_KeyLength)
		{
		}

		uint32 m_KeyLength = 4096;
	};

	struct CPublicKeySettings_EC_secp256r1
	{
	};

	struct CPublicKeySettings_EC_secp384r1
	{
	};

	struct CPublicKeySettings_EC_secp521r1
	{
	};

	struct CPublicKeySettings_EC_X25519
	{
	};

	using CPublicKeySetting = NStorage::TCStreamableVariant
		<
			EPublicKeyType
			, NStorage::TCMember<CPublicKeySettings_RSA, EPublicKeyType_RSA>
			, NStorage::TCMember<CPublicKeySettings_EC_secp256r1, EPublicKeyType_EC_secp256r1>
			, NStorage::TCMember<CPublicKeySettings_EC_secp384r1, EPublicKeyType_EC_secp384r1>
			, NStorage::TCMember<CPublicKeySettings_EC_secp521r1, EPublicKeyType_EC_secp521r1>
			, NStorage::TCMember<CPublicKeySettings_EC_X25519, EPublicKeyType_EC_X25519>
		>
	;

	class CPublicCrypto
	{
	public:
		static NContainer::CSecureByteVector fs_SignMessage
			(
				NContainer::CSecureByteVector const &_Message
				, NContainer::CSecureByteVector const &_KeyData
				, EDigestType _Digest = EDigestType_Automatic
			)
		;

		static bool fs_VerifySignature
			(
				NContainer::CSecureByteVector const &_Message
				, NContainer::CSecureByteVector const &_KeyData
				, NContainer::CSecureByteVector const &_Signature
				, EDigestType _Digest = EDigestType_Automatic
			)
		;

		static void fs_GenerateKeys
			(
				NContainer::CSecureByteVector &o_PrivateKeyData
				, NContainer::CSecureByteVector &o_PublicKeyData
				, CPublicKeySetting _KeySetting = CPublicKeySettings_EC_secp521r1{}
			)
		;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
