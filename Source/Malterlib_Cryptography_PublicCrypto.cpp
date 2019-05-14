#include "Malterlib_Cryptography_PublicCrypto.h"
#include "Malterlib_Cryptography_Certificate.h"

#include <Mib/Cryptography/BoringSSL>

namespace NMib::NCryptography
{
	using namespace NBoringSSL;

	NContainer::CSecureByteVector CPublicCrypto::fs_SignMessage(NContainer::CSecureByteVector const &_Message, NContainer::CSecureByteVector const &_KeyData, EDigestType _Digest)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					EVP_PKEY *pKey = fg_LoadPrivateKeyFromDER(_KeyData);
					if (!pKey)
						DMibError(fg_GetExceptionStr("Could not load private key"));
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
						ERR_clear_error();
						NContainer::CSecureByteVector Digest;
						unsigned int Size = 0;
						if (EVP_Digest(_Message.f_GetArray(), _Message.f_GetLen(), Digest.f_GetArray(EVP_MD_size(Md)), &Size, Md, nullptr) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Error computing digest"));
						if (Size > Digest.f_GetLen())
							DMibError(fg_GetExceptionStr("Size of hash exceeded maximum hash size"));

						ERR_clear_error();
						ECDSA_SIG *pSignature = ECDSA_do_sign(Digest.f_GetArray(), Digest.f_GetLen(), pECKey);
						if (!pSignature)
							DMibErrorCryptography(fg_GetExceptionStr("Signing failed"));
						auto Cleanup3 = g_OnScopeExit > [&]
							{
								ECDSA_SIG_free(pSignature);
							}
						;

						ERR_clear_error();
						aint Length = i2d_ECDSA_SIG(pSignature, nullptr);
						if (Length == 0)
							DMibErrorCryptography(fg_GetExceptionStr("Error computing length of signature"));

						ERR_clear_error();
						unsigned char *pArray = Signature.f_GetArray(Length);
						if (i2d_ECDSA_SIG(pSignature, &pArray) != Length)
							DMibErrorCryptography(fg_GetExceptionStr("Error converting signature to bytes"));
					}
					else
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
					}
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
					if (!pKey)
						DMibError(fg_GetExceptionStr("Could not load public key"));
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
					if (EC_KEY *pECKey = EVP_PKEY_get0_EC_KEY(pKey))
					{
						unsigned int Size = 0;
						ERR_clear_error();
						if (EVP_Digest(_Message.f_GetArray(), _Message.f_GetLen(), Digest.f_GetArray(EVP_MD_size(Md)), &Size, Md, nullptr) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Error computing digest"));
						if (Size > Digest.f_GetLen())
							DMibError(fg_GetExceptionStr("Size of hash exceeded maximum hash size"));

						ERR_clear_error();
						ECDSA_SIG *Signature = ECDSA_SIG_from_bytes(_Signature.f_GetArray(), _Signature.f_GetLen());
						if (!Signature)
							DMibErrorCryptography(fg_GetExceptionStr("Error unpacking signature"));
						auto Cleanup3 = g_OnScopeExit > [&]
							{
								ECDSA_SIG_free(Signature);
							}
						;

						ERR_clear_error();
						mint Result = ECDSA_do_verify(Digest.f_GetArray(), Digest.f_GetLen(), Signature, pECKey);
						if (Result & ~1)
							DMibErrorCryptography(fg_GetExceptionStr("EVP_DigestVerifyFinal failed"));
						return Result == 1;
					}
					else
					{
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
					}

					o_PrivateKeyData = fg_ConvertPrivateKeyToDER(pKey);
					o_PublicKeyData = fg_ConvertPublicKeyToDER(pKey);
				}
			)
		;
	}
}
