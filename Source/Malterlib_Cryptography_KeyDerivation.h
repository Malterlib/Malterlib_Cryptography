#pragma once

#include "Malterlib_Cryptography_MessageAuthentication.h"
#include "Malterlib_Cryptography_Exception.h"

#include <Mib/Storage/Variant>

namespace NMib::NCryptography
{
	enum ECryptoType
	{
		ECryptoType_AES_256_CBC
		, ECryptoType_AES_128_CBC
		, ECryptoType_AES_256_OFB	// Be careful (stream cipher)
		, ECryptoType_AES_128_OFB	// Be careful (stream cipher)
		, ECryptoType_DES_EDE3_CBC	// Be careful, only to be used for compatibility with legacy systems (weak croypto)
		, ECryptoType_AES_256_ECB	// Be careful, only to be used for compatibility with legacy systems (ECB mode)
		, ECryptoType_AES_128_ECB	// Be careful, only to be used for compatibility with legacy systems (ECB mode)
//			, ECryptoType_AES_128_CTR // Needs to have interface for specifying counter
//			, ECryptoType_AES_256_CTR // Needs to have interface for specifying counter
//			, ECryptoType_AES_256_XTS // Needs to have interface for specifying counter
	};

	enum EKeyDerivationType
	{
		EKeyDerivationType_Scrypt
		, EKeyDerivationType_PKCS5_PBKDF2_HMAC
		, EKeyDerivationType_PKCS5_Deprecated
	};

	struct CKeyDerivationSettings_Scrypt
	{
		EDigestType m_Digest = EDigestType_SHA512;
		uint64 m_Workload = 1 << 15; // (N)
		uint64 m_Ratio = 8; // (r)
		uint64 m_Parallel = 1; // (p)
		umint m_MaxMemory = 1024 * 1024 * 64;
	};

	struct CKeyDerivationSettings_PKCS5_PBKDF2_HMAC
	{
		EDigestType m_Digest = EDigestType_SHA512;
		uint32 m_Rounds = 10000;
	};

	struct CKeyDerivationSettings_PKCS5_Deprecated
	{
		EDigestType m_Digest = EDigestType_SHA256;
		uint32 m_Rounds = 1 << 17;
	};

	using CKeyDerivationSettings = NStorage::TCStreamableVariant
		<
			EKeyDerivationType
			, NStorage::TCMember<CKeyDerivationSettings_Scrypt, EKeyDerivationType_Scrypt>
			, NStorage::TCMember<CKeyDerivationSettings_PKCS5_PBKDF2_HMAC, EKeyDerivationType_PKCS5_PBKDF2_HMAC>
		>
	;

	struct CEncryptKeyIV
	{
		CEncryptKeyIV
			(
				NContainer::CSecureByteVector const &_Key
				, NContainer::CSecureByteVector const &_IV
				, ECryptoType _Crypto = ECryptoType_AES_256_CBC
			)
		;

		static CEncryptKeyIV fs_GenerateKeyIV
			(
				NStr::CStrSecure const &_Password
				, NContainer::CSecureByteVector const &_Salt
				, CKeyDerivationSettings_PKCS5_Deprecated const &_Settings
				, ECryptoType _Crypto = ECryptoType_AES_256_CBC
			)
		;

		static uint32 fs_GetKeyLen(ECryptoType _Crypto);
		static uint32 fs_GetIVLen(ECryptoType _Crypto);
		static uint32 fs_GetHMACKeyLen(EDigestType _Digest);
		static uint32 fs_GetBlockSize(ECryptoType _Crypto);
		static NContainer::CSecureByteVector fs_GetRandomKey(ECryptoType _Crypto);
		static NContainer::CSecureByteVector fs_GetRandomIV(ECryptoType _Crypto);
		static NContainer::CSecureByteVector fs_GetRandomHMACKey(EDigestType _Digest);

		NContainer::CSecureByteVector const m_Key;
		NContainer::CSecureByteVector const m_IV;
		ECryptoType m_Crypto;
	};

	NContainer::CSecureByteVector fg_DeriveKey
		(
			NStr::CStrSecure const &_Password
			, NContainer::CSecureByteVector const &_PasswordSalt
			, CKeyDerivationSettings const &_Settings
			, umint _KeyLen
		)
	;

	struct CKeyExpansion
	{
		CKeyExpansion
			(
				NStr::CStrSecure const &_Password
				, NContainer::CSecureByteVector const &_PasswordSalt
				, CKeyDerivationSettings const &_Settings
				, NContainer::CSecureByteVector const &_ExpansionSalt
				, EDigestType _Digest = EDigestType_SHA512
			)
		;
		CKeyExpansion
			(
				NContainer::CSecureByteVector const &_Key
				, NContainer::CSecureByteVector const &_ExpansionSalt
				, EDigestType _Digest = EDigestType_SHA512
			)
		;
		~CKeyExpansion();

		CEncryptKeyIV f_GetKeyIV(ECryptoType _Crypto = ECryptoType_AES_256_CBC) const;
		NContainer::CSecureByteVector f_GetHMACKey(EDigestType _Digest = EDigestType_SHA512) const;

		NContainer::CSecureByteVector f_GetKey(NStr::CStr const &_Label, umint _Length) const;

	private:
		EDigestType mp_Digest = EDigestType_None;
		NContainer::CSecureByteVector mp_PseudoRandomKey;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
