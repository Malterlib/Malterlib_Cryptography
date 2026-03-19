#include "Malterlib_Cryptography_KeyDerivation.h"

#include <Mib/Cryptography/BoringSSL>

namespace NMib::NCryptography
{
	using namespace NBoringSSL;

	CEncryptKeyIV::CEncryptKeyIV(NContainer::CSecureByteVector const &_Key, NContainer::CSecureByteVector const &_IV, ECryptoType _Crypto)
		: m_Key(_Key)
		, m_IV(_IV)
		, m_Crypto(_Crypto)
	{
	}

	CEncryptKeyIV CEncryptKeyIV::fs_GenerateKeyIV
		(
			NStr::CStrSecure const &_Password
			, NContainer::CSecureByteVector const &_Salt
			, CKeyDerivationSettings_PKCS5_Deprecated const &_Settings
			, ECryptoType _Crypto
		)
	{

		return fg_RunProtectRegisters
			(
				[&]() -> CEncryptKeyIV
				{
					EVP_CIPHER const* pCipher = fg_GetCipher(_Crypto);
					EVP_MD const *pDigest = fg_GetDigest(_Settings.m_Digest);
					uint8 Key[EVP_MAX_KEY_LENGTH];
					uint8 IV[EVP_MAX_IV_LENGTH];
					if (!_Salt.f_IsEmpty() && _Salt.f_GetLen() != 8)
						DMibErrorCryptography("Salt needs to be 8 bytes for EKeyDerivationType_PKCS5_Deprecated");

					ERR_clear_error();
					if
						(
							!EVP_BytesToKey
							(
								pCipher
								, pDigest
								, !_Salt.f_IsEmpty() ? (uint8_t const *)_Salt.f_GetArray() : nullptr
								, (uint8_t const *)_Password.f_GetStr()
								, _Password.f_GetLen()
								, _Settings.m_Rounds
								, Key
								, IV
							)
						)
					{
						DMibErrorCryptography(fg_GetExceptionStr("Failed to generate key, iv for EKeyDerivationType_PKCS5_Deprecated"));
					}
					return {NContainer::CSecureByteVector(Key, EVP_CIPHER_key_length(pCipher)), NContainer::CSecureByteVector(IV, EVP_CIPHER_iv_length(pCipher)), _Crypto};
				}
			)
		;
	}

	uint32 CEncryptKeyIV::fs_GetKeyLen(ECryptoType _Crypto)
	{
		return EVP_CIPHER_key_length(fg_GetCipher(_Crypto));
	}

	uint32 CEncryptKeyIV::fs_GetIVLen(ECryptoType _Crypto)
	{
		return EVP_CIPHER_iv_length(fg_GetCipher(_Crypto));
	}

	uint32 CEncryptKeyIV::fs_GetHMACKeyLen(EDigestType _Digest)
	{
		return (uint32)EVP_MD_size(fg_GetDigest(_Digest));
	}

	uint32 CEncryptKeyIV::fs_GetBlockSize(ECryptoType _Crypto)
	{
		return EVP_CIPHER_block_size(fg_GetCipher(_Crypto));
	}

	NContainer::CSecureByteVector CEncryptKeyIV::fs_GetRandomKey(ECryptoType _Crypto)
	{
		NContainer::CSecureByteVector Key;
		Key.f_SetLen(fs_GetKeyLen(_Crypto));
		NSys::fg_Security_GenerateHighEntropyData(Key.f_GetArray(), Key.f_GetLen());
		return fg_Move(Key);
	}

	NContainer::CSecureByteVector CEncryptKeyIV::fs_GetRandomIV(ECryptoType _Crypto)
	{
		NContainer::CSecureByteVector Key;
		Key.f_SetLen(fs_GetIVLen(_Crypto));
		NSys::fg_Security_GenerateHighEntropyData(Key.f_GetArray(), Key.f_GetLen());
		return fg_Move(Key);
	}

	NContainer::CSecureByteVector CEncryptKeyIV::fs_GetRandomHMACKey(EDigestType _Digest)
	{
		NContainer::CSecureByteVector Key;
		Key.f_SetLen(fs_GetHMACKeyLen(_Digest));
		NSys::fg_Security_GenerateHighEntropyData(Key.f_GetArray(), Key.f_GetLen());
		return fg_Move(Key);
	}


	NContainer::CSecureByteVector fg_DeriveKey
		(
			NStr::CStrSecure const &_Password
			, NContainer::CSecureByteVector const &_PasswordSalt
			, CKeyDerivationSettings const &_Settings
			, umint _KeyLen
		)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> NContainer::CSecureByteVector
				{
					NContainer::CSecureByteVector Key;
					Key.f_SetLen(_KeyLen);
					switch (_Settings.f_GetTypeID())
					{
					case EKeyDerivationType_Scrypt:
						{
							auto const &Settings = _Settings.f_Get<EKeyDerivationType_Scrypt>();
							ERR_clear_error();
							if
								(
									!EVP_PBE_scrypt_with_digest
									(
										_Password.f_GetStr()
										, _Password.f_GetLen()
										, _PasswordSalt.f_GetArray()
										, _PasswordSalt.f_GetLen()
										, Settings.m_Workload
										, Settings.m_Ratio
										, Settings.m_Parallel
										, Settings.m_MaxMemory
										, fg_GetDigest(Settings.m_Digest)
										, Key.f_GetArray()
										, _KeyLen
									)
								)
							{
								DMibErrorCryptography(fg_GetExceptionStr("Failed to generate key using scrypt"));
							}
						}
						break;
					case EKeyDerivationType_PKCS5_PBKDF2_HMAC:
						{
							auto const &Settings = _Settings.f_Get<EKeyDerivationType_PKCS5_PBKDF2_HMAC>();
							ERR_clear_error();
							if
								(
									!PKCS5_PBKDF2_HMAC
									(
										_Password.f_GetStr()
										, _Password.f_GetLen()
										, _PasswordSalt.f_GetArray()
										, _PasswordSalt.f_GetLen()
										, Settings.m_Rounds
										, fg_GetDigest(Settings.m_Digest)
										, _KeyLen
										, Key.f_GetArray()
									 )
								)
							{
								DMibErrorCryptography(fg_GetExceptionStr("Failed to generate key using PKCS5_PBKDF2_HMAC"));
							}
						}
						break;
					default:
						DMibError("Unknown key derivation type");
						break;
					}
					return Key;
				}
			)
		;
	}

	CKeyExpansion::CKeyExpansion
		(
			NStr::CStrSecure const &_Password
			, NContainer::CSecureByteVector const &_PasswordSalt
			, CKeyDerivationSettings const &_Settings
			, NContainer::CSecureByteVector const &_ExpansionSalt
			, EDigestType _Digest
		)
		: CKeyExpansion{fg_DeriveKey(_Password, _PasswordSalt, _Settings, EVP_MD_size(fg_GetDigest(_Digest))), _ExpansionSalt, _Digest}
	{
	}

	CKeyExpansion::CKeyExpansion
		(
			NContainer::CSecureByteVector const &_Key
			, NContainer::CSecureByteVector const &_ExpansionSalt
			, EDigestType _Digest
		)
		: mp_Digest{_Digest}
	{
		fg_RunProtectRegisters
			(
				[&]()
				{
					EVP_MD const *pDigest = fg_GetDigest(_Digest);
					umint ExpectedKeySize = EVP_MD_size(pDigest);
					mp_PseudoRandomKey.f_SetLen(ExpectedKeySize);
					size_t KeySize = 0;
					if (!HKDF_extract(mp_PseudoRandomKey.f_GetArray(), &KeySize, pDigest, _Key.f_GetArray(), _Key.f_GetLen(), _ExpansionSalt.f_GetArray(), _ExpansionSalt.f_GetLen()))
						DMibErrorCryptography(fg_GetExceptionStr("Failed to call HKDF_extract"));
					DMibCheck(KeySize == ExpectedKeySize);
				}
			)
		;
	}

	CKeyExpansion::~CKeyExpansion() = default;

	CEncryptKeyIV CKeyExpansion::f_GetKeyIV(ECryptoType _Crypto) const
	{
		EVP_CIPHER const *pCipher = fg_GetCipher(_Crypto);
		return {f_GetKey("EncryptKey", EVP_CIPHER_key_length(pCipher)), f_GetKey("EncryptIV", EVP_CIPHER_iv_length(pCipher)), _Crypto};
	}

	NContainer::CSecureByteVector CKeyExpansion::f_GetHMACKey(EDigestType _Digest) const
	{
		EVP_MD const *pDigest = fg_GetDigest(_Digest);
		return f_GetKey("HMACKey", EVP_MD_size(pDigest));
	}

	NContainer::CSecureByteVector CKeyExpansion::f_GetKey(NStr::CStr const &_Label, umint _Length) const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> NContainer::CSecureByteVector
				{
					EVP_MD const *pDigest = fg_GetDigest(mp_Digest);
					NContainer::CSecureByteVector Result;
					Result.f_SetLen(_Length);
					if
						(
							!HKDF_expand
							(
								Result.f_GetArray()
								, _Length
								, pDigest
								, mp_PseudoRandomKey.f_GetArray()
								, mp_PseudoRandomKey.f_GetLen()
								, (uint8_t const *)_Label.f_GetStr()
								, _Label.f_GetLen()
							)
						)
					{
						DMibErrorCryptography(fg_GetExceptionStr("Failed to get key from HKDF_expand"));
					}
					return Result;
				}
			)
		;
	}
}
