#include "Malterlib_Cryptography_PublicCrypto.h"
#include "Malterlib_Cryptography_Certificate.h"

#include <Mib/Cryptography/BoringSSL>

namespace NMib::NCryptography
{
	using namespace NBoringSSL;

	bool CPublicKeySettings_RSA::operator == (CPublicKeySettings_RSA const &_Right) const
	{
		return m_KeyLength == _Right.m_KeyLength;
	}

	bool CPublicKeySettings_RSA::operator < (CPublicKeySettings_RSA const &_Right) const
	{
		return m_KeyLength < _Right.m_KeyLength;
	}

	bool CPublicKeySettings_EC_secp256r1::operator == (CPublicKeySettings_EC_secp256r1 const &_Right) const
	{
		return true;
	}

	bool CPublicKeySettings_EC_secp256r1::operator < (CPublicKeySettings_EC_secp256r1 const &_Right) const
	{
		return false;
	}

	bool CPublicKeySettings_EC_secp384r1::operator == (CPublicKeySettings_EC_secp384r1 const &_Right) const
	{
		return true;
	}

	bool CPublicKeySettings_EC_secp384r1::operator < (CPublicKeySettings_EC_secp384r1 const &_Right) const
	{
		return false;
	}

	bool CPublicKeySettings_EC_secp521r1::operator == (CPublicKeySettings_EC_secp521r1 const &_Right) const
	{
		return true;
	}

	bool CPublicKeySettings_EC_secp521r1::operator < (CPublicKeySettings_EC_secp521r1 const &_Right) const
	{
		return false;
	}

	bool CPublicKeySettings_EC_X25519::operator == (CPublicKeySettings_EC_X25519 const &_Right) const
	{
		return true;
	}

	bool CPublicKeySettings_EC_X25519::operator < (CPublicKeySettings_EC_X25519 const &_Right) const
	{
		return false;
	}

	NContainer::CSecureByteVector CPublicCrypto::fs_GetPublicKeyFromPrivateKey(NContainer::CSecureByteVector const &_PrivateKey)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					EVP_PKEY *pKey = fg_LoadPrivateKeyFromDER(_PrivateKey);
					auto Cleanup1 = g_OnScopeExit > [&]
						{
							EVP_PKEY_free(pKey);
						}
					;

					return fg_ConvertPublicKeyToDER(pKey);
				}
			)
		;
	}

	CPublicCrypto::CPublicKeyParameters CPublicCrypto::fs_GetPublicKeyParameters(NContainer::CSecureByteVector const &_Key)
	{
		EVP_PKEY *pKey = fg_LoadPublicKeyFromDER(_Key);
		auto Cleanup1 = g_OnScopeExit > [&]
			{
				EVP_PKEY_free(pKey);
			}
		;

		mint ExpectedBytes = (EVP_PKEY_bits(pKey) + 7) / 8;

		auto fConvertBigNum = [&](BIGNUM const *_pBigNum, bool _bPad) -> NContainer::CSecureByteVector
			{
				NContainer::CSecureByteVector Output;

				mint nBytes = BN_num_bytes(_pBigNum);

				if (_bPad)
				{
					if (nBytes > ExpectedBytes)
						DMibErrorCryptography("Invalid EC key point which is too big");

					Output.f_SetLen(ExpectedBytes);

					for (mint i = 0; i < (ExpectedBytes - nBytes); ++i)
						Output[i] = 0;

					BN_bn2bin(_pBigNum, Output.f_GetArray() + (ExpectedBytes - nBytes));
				}
				else
				{
					Output.f_SetLen(nBytes);
					BN_bn2bin(_pBigNum, Output.f_GetArray());
				}

				return Output;
			}
		;

		if (EC_KEY *pECKey = EVP_PKEY_get0_EC_KEY(pKey))
		{
			EC_POINT const *pPublicKey = EC_KEY_get0_public_key(pECKey);

			BIGNUM *pCoordinateX = BN_new();
			BIGNUM *pCoordinateY = BN_new();

			auto Cleanup = g_OnScopeExit > [&]
				{
					BN_free(pCoordinateX);
					BN_free(pCoordinateY);
				}
			;

			ERR_clear_error();
			if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(pECKey), pPublicKey, pCoordinateX, pCoordinateY, nullptr))
				DMibErrorCryptography(fg_GetExceptionStr("Error getting EC public key point coordinates"));

			CPublicKeyParameters_EC Params;
			Params.m_CoordinateX = fConvertBigNum(pCoordinateX, true);
			Params.m_CoordinateY = fConvertBigNum(pCoordinateY, true);

			return fg_Move(Params);
		}
		else if (RSA *pRSA = EVP_PKEY_get0_RSA(pKey))
		{
			const BIGNUM *pModulus, *pExponent;
			RSA_get0_key(pRSA, &pModulus, &pExponent, nullptr);

			CPublicKeyParameters_RSA Params;
			Params.m_Modulus = fConvertBigNum(pModulus, false);
			Params.m_Exponent = fConvertBigNum(pExponent, false);

			return fg_Move(Params);
		}
		else
			DMibErrorCryptography("Unsupported key type");
	}

	NContainer::CSecureByteVector CPublicCrypto::fs_SignMessage(NContainer::CSecureByteVector const &_Message, NContainer::CSecureByteVector const &_KeyData, EDigestType _Digest)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					EVP_PKEY *pKey = fg_LoadPrivateKeyFromDER(_KeyData);
					auto Cleanup1 = g_OnScopeExit > [&]
						{
							EVP_PKEY_free(pKey);
						}
					;

					EVP_MD const *Md = fg_GetDigest(_Digest, pKey);
					ERR_clear_error();
					EVP_MD_CTX *Ctx = EVP_MD_CTX_create();
					if (!Ctx)
						DMibErrorCryptography(fg_GetExceptionStr("EVP_MD_CTX_create failed"));
					auto Cleanup2 = g_OnScopeExit > [&]
						{
							EVP_MD_CTX_destroy(Ctx);
						}
					;

					NContainer::CSecureByteVector Signature;
					ERR_clear_error();
					if (EVP_DigestSignInit(Ctx, NULL, Md, NULL, pKey) != 1)
						DMibErrorCryptography(fg_GetExceptionStr("EVP_DigestSignInit failed"));

					ERR_clear_error();
					if (EVP_DigestSignUpdate(Ctx, _Message.f_GetArray(), _Message.f_GetLen()) != 1)
						DMibErrorCryptography(fg_GetExceptionStr("EVP_DigestSignUpdate failed"));

					ERR_clear_error();
					size_t Len;
					if (EVP_DigestSignFinal(Ctx, nullptr, &Len) != 1)
						DMibErrorCryptography(fg_GetExceptionStr("EVP_DigestSignFinal failed"));

					ERR_clear_error();
					if (EVP_DigestSignFinal(Ctx, Signature.f_GetArray(Len), &Len) != 1)
						DMibErrorCryptography(fg_GetExceptionStr("EVP_DigestSignFinal failed"));

					Signature.f_SetLen(Len);
					return Signature;
				}
			)
		;
	}

	NContainer::CSecureByteVector CPublicCrypto::fs_SignMessageRawSignature(NContainer::CSecureByteVector const &_Message, NContainer::CSecureByteVector const &_KeyData, EDigestType _Digest)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					EVP_PKEY *pKey = fg_LoadPrivateKeyFromDER(_KeyData);
					auto Cleanup1 = g_OnScopeExit > [&]
						{
							EVP_PKEY_free(pKey);
						}
					;

					EVP_MD const *Md = fg_GetDigest(_Digest, pKey);
					ERR_clear_error();
					EVP_MD_CTX *Ctx = EVP_MD_CTX_create();
					if (!Ctx)
						DMibErrorCryptography(fg_GetExceptionStr("EVP_MD_CTX_create failed"));

					auto Cleanup2 = g_OnScopeExit > [&]
						{
							EVP_MD_CTX_destroy(Ctx);
						}
					;

					NContainer::CSecureByteVector Signature;

					if (EC_KEY *pECKey = EVP_PKEY_get0_EC_KEY(pKey))
					{
						mint ExpectedBytes = (EVP_PKEY_bits(pKey) + 7) / 8;

						ERR_clear_error();
						NContainer::CSecureByteVector Digest;
						unsigned int Size = 0;
						if (EVP_Digest(_Message.f_GetArray(), _Message.f_GetLen(), Digest.f_GetArray(EVP_MD_size(Md)), &Size, Md, nullptr) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Error computing digest"));
						if (Size > Digest.f_GetLen())
							DMibError("Size of hash exceeded maximum hash size");

						ERR_clear_error();
						ECDSA_SIG *pSignature = ECDSA_do_sign(Digest.f_GetArray(), Digest.f_GetLen(), pECKey);
						if (!pSignature)
							DMibErrorCryptography(fg_GetExceptionStr("Signing failed"));
						auto Cleanup3 = g_OnScopeExit > [&]
							{
								ECDSA_SIG_free(pSignature);
							}
						;

						Signature.f_SetLen(ExpectedBytes * 2);

						const BIGNUM *pComponentR, *pComponentS;
						ECDSA_SIG_get0(pSignature, &pComponentR, &pComponentS);

						mint nBytesComporentR = BN_num_bytes(pComponentR);
						mint nBytesComporentS = BN_num_bytes(pComponentS);

						if (nBytesComporentR > ExpectedBytes || nBytesComporentS > ExpectedBytes)
							DMibErrorCryptography("Invalid number of bytes in EC signature component");

						BN_bn2bin(pComponentR, Signature.f_GetArray() + (ExpectedBytes - BN_num_bytes(pComponentR)));
						BN_bn2bin(pComponentS, Signature.f_GetArray() + (ExpectedBytes*2 - BN_num_bytes(pComponentS)));
					}
					else if (RSA *pRSA = EVP_PKEY_get0_RSA(pKey))
					{
						ERR_clear_error();
						if (EVP_DigestSignInit(Ctx, NULL, Md, NULL, pKey) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("EVP_DigestSignInit failed"));

						ERR_clear_error();
						if (EVP_DigestSignUpdate(Ctx, _Message.f_GetArray(), _Message.f_GetLen()) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("EVP_DigestSignUpdate failed"));

						ERR_clear_error();
						size_t Len;
						if (EVP_DigestSignFinal(Ctx, nullptr, &Len) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("EVP_DigestSignFinal failed"));

						ERR_clear_error();
						if (EVP_DigestSignFinal(Ctx, Signature.f_GetArray(Len), &Len) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("EVP_DigestSignFinal failed"));

						Signature.f_SetLen(Len);
						return Signature;
					}
					else
						DMibErrorCryptography("Unsupported key type");
					return Signature;
				}
			)
		;
	}

	bool CPublicCrypto::fs_VerifySignature
		(
			NContainer::CSecureByteVector const &_Message
			, NContainer::CSecureByteVector const &_KeyData
			, NContainer::CSecureByteVector const &_Signature
			, EDigestType _Digest
		)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					EVP_PKEY *pKey = fg_LoadPublicKeyFromDER(_KeyData);
					auto Cleanup1 = g_OnScopeExit > [&]
						{
							EVP_PKEY_free(pKey);
						}
					;
					EVP_MD const *Md = fg_GetDigest(_Digest, pKey);

					ERR_clear_error();
					EVP_MD_CTX *Ctx = EVP_MD_CTX_create();
					if (!Ctx)
						DMibErrorCryptography(fg_GetExceptionStr("EVP_MD_CTX_create failed"));
					auto Cleanup2 = g_OnScopeExit > [&]
						{
							EVP_MD_CTX_destroy(Ctx);
						}
					;

					NContainer::CSecureByteVector Digest;

					ERR_clear_error();
					if (EVP_DigestVerifyInit(Ctx, NULL, Md, NULL, pKey) != 1)
						DMibErrorCryptography(fg_GetExceptionStr("EVP_DigestVerifyInit failed"));

					ERR_clear_error();
					if (EVP_DigestVerifyUpdate(Ctx, _Message.f_GetArray(), _Message.f_GetLen()) != 1)
						DMibErrorCryptography(fg_GetExceptionStr("EVP_DigestVerifyUpdate failed"));

					ERR_clear_error();
					int Result = EVP_DigestVerifyFinal(Ctx, _Signature.f_GetArray(), _Signature.f_GetLen());
					if (Result & ~0x01)
						DMibErrorCryptography(fg_GetExceptionStr("EVP_DigestVerifyFinal failed"));
					return Result == 1;
				}
			)
		;
	}

	void CPublicCrypto::fs_GenerateKeys(NContainer::CSecureByteVector &o_PrivateKeyData, NContainer::CSecureByteVector &o_PublicKeyData, CPublicKeySetting _KeySetting)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					ERR_clear_error();
					EVP_PKEY *pKey = EVP_PKEY_new();
					if (!pKey)
						DMibErrorCryptography(fg_GetExceptionStr("Error creating key (1)"));
					auto Cleanup0 = g_OnScopeExit > [&]
						{
							EVP_PKEY_free(pKey);
						}
					;
					CCertificateOptions Options;
					Options.m_KeySetting = _KeySetting;
					fg_GenerateKey(pKey, Options);

					switch (_KeySetting.f_GetTypeID())
					{
					case EPublicKeyType_EC_secp256r1:
					case EPublicKeyType_EC_secp384r1:
					case EPublicKeyType_EC_secp521r1:
					case EPublicKeyType_EC_X25519:
						ERR_clear_error();
						if (!EVP_PKEY_get0_EC_KEY(pKey)) //Did we get one?
							DMibErrorCryptography(fg_GetExceptionStr("Error getting EC_Key"));
						break;
					case EPublicKeyType_RSA:
						break;
					}

					o_PrivateKeyData = fg_ConvertPrivateKeyToDER(pKey);
					o_PublicKeyData = fg_ConvertPublicKeyToDER(pKey);
				}
			)
		;
	}

	CPublicKeySetting CPublicCrypto::fs_PublicKeySettingsFromPrivateKey(NContainer::CSecureByteVector const &_Key)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> CPublicKeySetting
				{
					EVP_PKEY *pKey = fg_LoadPrivateKeyFromDER(_Key);
					auto Cleanup1 = g_OnScopeExit > [&]
						{
							EVP_PKEY_free(pKey);
						}
					;

					auto KeyType = EVP_PKEY_id(pKey);

					switch (KeyType)
					{
					case EVP_PKEY_RSA: return CPublicKeySettings_RSA{uint32(EVP_PKEY_bits(pKey))};
					case EVP_PKEY_EC:
						{
							if (EC_KEY *pECKey = EVP_PKEY_get0_EC_KEY(pKey))
							{
								switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(pECKey)))
								{
								case NID_secp521r1: return CPublicKeySettings_EC_secp521r1{};
								case NID_secp384r1: return CPublicKeySettings_EC_secp384r1{};
								case NID_X9_62_prime256v1: return CPublicKeySettings_EC_secp256r1{};
								case NID_X25519: return CPublicKeySettings_EC_X25519{};
								}
							}
						}
						break;
					default: break;
					}
					DMibErrorCryptography("Unsupported key type");
				}
			)
		;
	}
}
