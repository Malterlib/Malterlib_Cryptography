
#include "Malterlib_Cryptography_BoringSSL.h"

namespace NMib::NCryptography
{
}

extern "C"
{
#if (DMibConfig_MemoryManager_Stats_EnableCategories || DMibConfig_MemoryManager_Stats_EnableCallstack)
	void *OPENSSL_malloc(size_t _Size)
	{
		return NMib::NMemory::CAllocator_NonTrackedHeap::f_Alloc(_Size);
	}

	void OPENSSL_free(void *_pPtr)
	{
		if (!_pPtr)
			return;

		mint Size = NMib::NMemory::CAllocator_NonTrackedHeap::f_Size(_pPtr);
		OPENSSL_cleanse(_pPtr, Size);

		return NMib::NMemory::CAllocator_NonTrackedHeap::f_Free(_pPtr, Size);
	}

	void *OPENSSL_realloc(void *_pPtr, size_t _NewSize)
	{
		if (_pPtr == NULL)
			return NMib::NMemory::CAllocator_NonTrackedHeap::f_Alloc(_NewSize);

		size_t OldSize = NMib::NMemory::CAllocator_NonTrackedHeap::f_Size(_pPtr);

		void *pMem = NMib::NMemory::CAllocator_NonTrackedHeap::f_Alloc(_NewSize);
		if (!pMem)
			return pMem;

		size_t ToCopy = _NewSize;
		if (OldSize < ToCopy)
			ToCopy = OldSize;

		memcpy(pMem, _pPtr, ToCopy);
		NMib::NMemory::CAllocator_NonTrackedHeap::f_Free(_pPtr, OldSize);

		return pMem;
	}
#else
	void *OPENSSL_malloc(size_t _Size)
	{
		return NMib::NMemory::fg_Alloc(_Size);
	}

	void OPENSSL_free(void *_pPtr)
	{
		if (!_pPtr)
			return;

		mint Size = NMib::NMemory::fg_Size(_pPtr);
		OPENSSL_cleanse(_pPtr, Size);

		return NMib::NMemory::fg_Free(_pPtr, Size);
	}

	void *OPENSSL_realloc(void *_pPtr, size_t _NewSize)
	{
		if (_pPtr == NULL)
			return NMib::NMemory::fg_Alloc(_NewSize);

		size_t OldSize = NMib::NMemory::fg_Size(_pPtr);

		void *pMem = NMib::NMemory::fg_Alloc(_NewSize);
		if (!pMem)
			return pMem;

		size_t ToCopy = _NewSize;
		if (OldSize < ToCopy)
			ToCopy = OldSize;

		memcpy(pMem, _pPtr, ToCopy);
		NMib::NMemory::fg_Free(_pPtr, OldSize);

		return pMem;
	}
#endif
	void *OPENSSL_zalloc(size_t size) {
		void *ret = OPENSSL_malloc(size);
		if (ret != NULL) {
			memset(ret, 0, size);
		}
		return ret;
	}

	void *OPENSSL_calloc(size_t num, size_t size) {
		if (size != 0 && num > SIZE_MAX / size) {
			OPENSSL_PUT_ERROR(CRYPTO, ERR_R_OVERFLOW);
			return NULL;
		}
		return OPENSSL_zalloc(num * size);
	}
}

namespace NMib::NCryptography::NBoringSSL
{
	namespace
	{
		struct CBoringSSLInit
		{
			CBoringSSLInit()
			{
				fg_RunProtectRegisters
					(
						[&]() -> decltype(auto)
						{
							SSL_library_init();
						}
					)
				;
			}
		};

		constinit NStorage::TCAggregate<CBoringSSLInit> g_SSLLowLevel = {DAggregateInit};
	}

	NStr::CStr fg_GetErrors()
	{
		NStr::CStr Errors;
		auto fAddError = [&](char const *_pError, size_t _StringLength)
			{
				NStr::fg_AddStrSep(Errors, NStr::CStr(_pError, _StringLength), DMibNewLine);
			}
		;
		using CAddErrorType = decltype(fAddError);

		ERR_print_errors_cb
			(
				[](char const *_pError, size_t _StringLength, void *_pContext) -> int
				{
					(*((CAddErrorType *)_pContext))(_pError, _StringLength);
					return 1;
				}
				, &fAddError
			)
		;

		return Errors;
	}

	void fg_Init()
	{
		*g_SSLLowLevel;
	}

	NStr::CStr fg_GetExceptionStr(NStr::CStr const &_Description)
	{
		NStr::CStr Errors = fg_GetErrors();

		if (Errors.f_IsEmpty())
			return _Description;

		return fg_Format("{}: {}", _Description, Errors);
	}

	EVP_CIPHER const *fg_GetCipher(ECryptoType _Crypto)
	{
		switch (_Crypto)
		{
		case ECryptoType_AES_256_CBC: return EVP_aes_256_cbc();
		case ECryptoType_AES_128_CBC: return EVP_aes_128_cbc();
		case ECryptoType_AES_256_OFB: return EVP_aes_256_ofb();
		case ECryptoType_AES_128_OFB: return EVP_aes_128_ofb();
		case ECryptoType_DES_EDE3_CBC: return EVP_des_ede3_cbc();
		case ECryptoType_AES_256_ECB: return EVP_aes_256_ecb();
		case ECryptoType_AES_128_ECB: return EVP_aes_128_ecb();
		//case ECryptoType_AES_128_CTR: return EVP_aes_128_ctr();
		//case ECryptoType_AES_256_CTR: return EVP_aes_256_ctr();
		//case ECryptoType_AES_256_XTS: return EVP_aes_256_xts();
		default: DMibErrorCryptography(fg_GetExceptionStr("Unknown cipher"));
		}
	}

	EVP_MD const *fg_GetDigest(EDigestType _Digest)
	{
		switch (_Digest)
		{
		case EDigestType_SHA256: return EVP_sha256();
		case EDigestType_SHA384: return EVP_sha384();
		case EDigestType_SHA512: return EVP_sha512();
		case EDigestType_SHA224: return EVP_sha224();
		case EDigestType_MD4: return EVP_md4();
		case EDigestType_MD5: return EVP_md5();
		case EDigestType_SHA1: return EVP_sha1();
		case EDigestType_SHA256_16: return EVP_sha256();
		default: DMibErrorCryptography(fg_GetExceptionStr("Unknown digest"));
		}
	}

	EVP_MD const *fg_GetDigest(EDigestType _Digest, EVP_PKEY *_pKey)
	{
		switch (_Digest)
		{
		case EDigestType_Automatic:
			{
				if (auto pRSA = EVP_PKEY_get1_RSA(_pKey))
				{
					auto RSASize = RSA_size(pRSA) * 8;
					RSA_free(pRSA);

					if (RSASize >= 12288)
						return EVP_sha512();
					else if (RSASize >= 4096)
						return EVP_sha384();
					else
						return EVP_sha256();
				}
				else if (auto pECKey = EVP_PKEY_get1_EC_KEY(_pKey))
				{
					auto CurveName = EC_GROUP_get_curve_name(EC_KEY_get0_group(pECKey));
					EC_KEY_free(pECKey);

					switch (CurveName)
					{
					case NID_secp521r1:
						return EVP_sha512();
					case NID_secp384r1:
						return EVP_sha384();
					case NID_X9_62_prime256v1:
					case NID_X25519:
						return EVP_sha256();
					}
				}
				return EVP_sha384();
			}
		case EDigestType_SHA256: return EVP_sha256();
		case EDigestType_SHA384: return EVP_sha384();
		case EDigestType_SHA512: return EVP_sha512();

		case EDigestType_SHA224:
		case EDigestType_SHA1:
		case EDigestType_SHA256_16:
		case EDigestType_MD5:
		case EDigestType_MD4:
		case EDigestType_None:
			break;
		}
		DMibNeverGetHere;
		return EVP_sha384();
	}

	EVP_PKEY *fg_LoadPrivateKeyFromDER(NContainer::CSecureByteVector const &_Data)
	{
		ERR_clear_error();

		BIO* pMemoryBio = BIO_new_mem_buf(const_cast<void*>(static_cast<void const*>(_Data.f_GetArray())), _Data.f_GetLen());
		if (!pMemoryBio)
			DMibErrorCryptography(fg_GetExceptionStr("Failed to create BIO buffer"));
		auto Cleanup0 = g_OnScopeExit / [&]
			{
				BIO_free(pMemoryBio);
			}
		;

		ERR_clear_error();
		EVP_PKEY* pKey = d2i_PrivateKey_bio(pMemoryBio, nullptr);
		if (!pKey)
			DMibErrorCryptography(fg_GetExceptionStr("Failed to read private key"));

		return pKey;
	}

	EVP_PKEY *fg_LoadPublicKeyFromDER(NContainer::CSecureByteVector const &_Data)
	{
		ERR_clear_error();

		BIO* pMemoryBio = BIO_new_mem_buf(const_cast<void*>(static_cast<void const*>(_Data.f_GetArray())), _Data.f_GetLen());
		if (!pMemoryBio)
			DMibErrorCryptography(fg_GetExceptionStr("Failed to create BIO buffer"));
		auto Cleanup0 = g_OnScopeExit / [&]
			{
				BIO_free(pMemoryBio);
			}
		;

		ERR_clear_error();
		EVP_PKEY *pKey = d2i_PUBKEY_bio(pMemoryBio, nullptr);
		if (!pKey)
			DMibErrorCryptography(fg_GetExceptionStr("Failed to read public key"));

		return pKey;
	}

	NContainer::CSecureByteVector fg_ConvertPrivateKeyToDER(EVP_PKEY *_pKey)
	{
		if (!_pKey)
			DMibErrorCryptography("Key in nullptr");

		ERR_clear_error();
		BIO* pMemoryBio = BIO_new(BIO_s_mem());
		if (!pMemoryBio)
			DMibErrorCryptography(fg_GetExceptionStr("Error creating BIO"));
		auto Cleanup = g_OnScopeExit / [&]
			{
				BIO_free(pMemoryBio);
			}
		;

		ERR_clear_error();
		if (!i2d_PrivateKey_bio(pMemoryBio, _pKey))
			DMibErrorCryptography(fg_GetExceptionStr("Error writing private key to BIO"));

		NContainer::CSecureByteVector Return;
		Return.f_SetLen(pMemoryBio->num_write);
		ERR_clear_error();
		if (!BIO_read(pMemoryBio, Return.f_GetArray(), Return.f_GetLen()))
			DMibErrorCryptography(fg_GetExceptionStr("Error reading private key from BIO"));
		return Return;
	}

	NContainer::CSecureByteVector fg_ConvertPublicKeyToDER(EVP_PKEY *_pKey)
	{
		if (!_pKey)
			DMibErrorCryptography("Key in nullptr");

		ERR_clear_error();
		BIO* pMemoryBio = BIO_new(BIO_s_mem());
		if (!pMemoryBio)
			DMibErrorCryptography(fg_GetExceptionStr("Error creating BIO"));
		auto Cleanup = g_OnScopeExit / [&]
			{
				BIO_free(pMemoryBio);
			}
		;

		ERR_clear_error();
		if (!i2d_PUBKEY_bio(pMemoryBio, _pKey))
			DMibErrorCryptography(fg_GetExceptionStr("Error writing public key to BIO"));

		NContainer::CSecureByteVector Return;
		Return.f_SetLen(pMemoryBio->num_write);
		ERR_clear_error();
		if (!BIO_read(pMemoryBio, Return.f_GetArray(), Return.f_GetLen()))
			DMibErrorCryptography(fg_GetExceptionStr("Error reading private key from BIO"));
		return Return;
	}

	void fg_GenerateKey(EVP_PKEY *_pKey, CCertificateOptions const &_Options)
	{
		switch (_Options.m_KeySetting.f_GetTypeID())
		{
		case EPublicKeyType_RSA:
			{
				ERR_clear_error();
				RSA *pRSA = RSA_generate_key(_Options.m_KeySetting.f_Get<EPublicKeyType_RSA>().m_KeyLength, RSA_F4, nullptr, nullptr);
				if (!pRSA)
					DMibErrorCryptography(fg_GetExceptionStr("Error generating RSA key"));
				ERR_clear_error();
				if (!EVP_PKEY_assign_RSA(_pKey, pRSA))
					DMibErrorCryptography(fg_GetExceptionStr("Error assigning RSA key"));
				pRSA = nullptr;
			}
			break;
		case EPublicKeyType_EC_secp256r1:
		case EPublicKeyType_EC_secp384r1:
		case EPublicKeyType_EC_secp521r1:
		case EPublicKeyType_EC_X25519:
			{
				ERR_clear_error();
				EC_KEY *pECKey;

				int CurveName = NID_secp521r1;
				switch (_Options.m_KeySetting.f_GetTypeID())
				{
				case EPublicKeyType_EC_secp256r1:
					CurveName = NID_X9_62_prime256v1;
					break;
				case EPublicKeyType_EC_secp384r1:
					CurveName = NID_secp384r1;
					break;
				case EPublicKeyType_EC_secp521r1:
					CurveName = NID_secp521r1;
					break;
				case EPublicKeyType_EC_X25519:
					CurveName = NID_X25519;
					break;
				default:
					DMibNeverGetHere;
					break;
				}

				ERR_clear_error();
				pECKey = EC_KEY_new_by_curve_name(CurveName);
				if (!pECKey)
					DMibErrorCryptography(fg_GetExceptionStr("Error creating elliptic curve key"));
				auto Cleanup = g_OnScopeExit / [&]
					{
						EC_KEY_free(pECKey);
					}
				;
				ERR_clear_error();
				if (EC_KEY_generate_key(pECKey) != 1)
					DMibErrorCryptography(fg_GetExceptionStr("Error generating elliptic curve key"));
				EC_KEY_set_asn1_flag(pECKey, OPENSSL_EC_NAMED_CURVE);
				ERR_clear_error();
				if (!EVP_PKEY_assign_EC_KEY(_pKey, pECKey))
					DMibErrorCryptography(fg_GetExceptionStr("Error assigning elliptic curve key"));
				Cleanup.f_Clear();
			}
			break;
		default:
			DMibErrorCryptography("Invalid key type");
		}
	}

	X509 *fg_LoadCertificate(NContainer::CByteVector const &_CertificateData)
	{
		if (_CertificateData.f_IsEmpty())
			DMibErrorCryptography("Empty certificate data");

		ERR_clear_error();
		BIO* pMemoryBio = BIO_new_mem_buf( const_cast<void *>(static_cast<void const *>(_CertificateData.f_GetArray())), _CertificateData.f_GetLen());
		if (!pMemoryBio)
			DMibErrorCryptography(fg_GetExceptionStr("Error creating BIO buffer"));
		auto Cleanup = g_OnScopeExit / [&]
			{
				BIO_free(pMemoryBio);
			}
		;

		ERR_clear_error();
		X509 *pCertificate = PEM_read_bio_X509(pMemoryBio, nullptr, nullptr, nullptr);;
		if (!pCertificate)
			DMibErrorCryptography(fg_GetExceptionStr("Error reading x509 certificate"));

		return pCertificate;
	}

	X509_CRL *fg_LoadCrl(NContainer::CByteVector const &_CertificateData)
	{
		if (_CertificateData.f_IsEmpty())
			DMibErrorCryptography("Empty CRL data");

		ERR_clear_error();
		BIO* pMemoryBio = BIO_new_mem_buf( const_cast<void *>(static_cast<void const *>(_CertificateData.f_GetArray())), _CertificateData.f_GetLen());
		if (!pMemoryBio)
			DMibErrorCryptography(fg_GetExceptionStr("Error creating BIO buffer"));
		auto Cleanup = g_OnScopeExit / [&]
			{
				BIO_free(pMemoryBio);
			}
		;

		ERR_clear_error();
		X509_CRL *pCRL = PEM_read_bio_X509_CRL(pMemoryBio, nullptr, nullptr, nullptr);;
		if (!pCRL)
			DMibErrorCryptography(fg_GetExceptionStr("Error reading x509 certificate"));

		return pCRL;
	}

	NContainer::CByteVector fg_ConvertX509ToBinary(X509 *_pCertificate)
	{
		if (!_pCertificate)
			DMibErrorCryptography("x509 certificate in nullptr");

		ERR_clear_error();
		BIO* pMemoryBio = BIO_new(BIO_s_mem());
		if (!pMemoryBio)
			DMibErrorCryptography(fg_GetExceptionStr("Error creating BIO"));
		auto Cleanup = g_OnScopeExit / [&]
			{
				BIO_free(pMemoryBio);
			}
		;

		ERR_clear_error();
		if (!PEM_write_bio_X509(pMemoryBio, _pCertificate))
			DMibErrorCryptography(fg_GetExceptionStr("Error writing certificate to BIO"));

		NContainer::CByteVector Return;
		Return.f_SetLen(pMemoryBio->num_write);
		ERR_clear_error();
		if (!BIO_read(pMemoryBio, Return.f_GetArray(), Return.f_GetLen()))
			DMibErrorCryptography(fg_GetExceptionStr("Error reading certificate from BIO"));
		return Return;
	}

	namespace
	{
		bool fg_IsValidDateTime(int _Years, int _Months, int _Days, int _Hours, int _Minutes, int _Seconds)
		{
			return fg_Clamp(_Months, 1, 12) == _Months
				&& fg_Clamp(_Days, 1, NTime::CTimeConvert::fs_GetDaysInMonth(_Years, _Months - 1)) == _Days
				&& fg_Clamp(_Hours, 0, 23) == _Hours
				&& fg_Clamp(_Minutes, 0, 59) == _Minutes
				&& fg_Clamp(_Seconds, 0, 59) == _Seconds
			;
		}
	}

	NTime::CTime fg_ConvertFromASN1Time(ASN1_TIME const *_pTime)
	{
		if (!_pTime)
			return NTime::CTime::fs_StartOfTime();

		if (_pTime->type == V_ASN1_UTCTIME)
		{
			if (_pTime->length < 10)
				return NTime::CTime::fs_StartOfTime();

			ch8 const *pData = (ch8 const *)_pTime->data;

			for (int i = 0; i < 10; ++i)
			{
				if (!NStr::fg_CharIsNumber(pData[i]))
					return NTime::CTime::fs_StartOfTime();
			}

			int Years = (pData[0] - '0') * 10 + (pData[1] - '0');
			if (Years < 50)
				Years += 100;
			Years += 1900;

			int Months = (pData[2] - '0') * 10 + (pData[3] - '0');
			int Days = (pData[4] - '0') * 10 + (pData[5] - '0');
			int Hours = (pData[6] - '0') * 10 + (pData[7] - '0');
			int Minutes = (pData[8] - '0') * 10 + (pData[9] - '0');
			int Seconds = 0;

			if (_pTime->length >= 12 && NStr::fg_CharIsNumber(pData[10]) && NStr::fg_CharIsNumber(pData[11]))
				Seconds = (pData[10] - '0') * 10 + (pData[11] - '0');

			if (!fg_IsValidDateTime(Years, Months, Days, Hours, Minutes, Seconds))
				return NTime::CTime::fs_StartOfTime();

			return NTime::CTimeConvert::fs_CreateTime(Years, Months, Days, Hours, Minutes, Seconds);
		}
		else if (_pTime->type == V_ASN1_GENERALIZEDTIME)
		{
			if (_pTime->length < 12)
				return NTime::CTime::fs_StartOfTime();

			ch8 const *pData = (ch8 const *)_pTime->data;

			for (int i = 0; i < 12; ++i)
			{
				if (!NStr::fg_CharIsNumber(pData[i]))
					return NTime::CTime::fs_StartOfTime();
			}

			int Years = (pData[0] - '0') * 1000 + (pData[1] - '0') * 100 + (pData[2] - '0') * 10 + (pData[3] - '0');
			int Months = (pData[4] - '0') * 10 + (pData[5] - '0');
			int Days = (pData[6] - '0') * 10 + (pData[7] - '0');
			int Hours = (pData[8] - '0') * 10 + (pData[9] - '0');
			int Minutes = (pData[10] - '0') * 10 + (pData[11] - '0');
			int Seconds = 0;

			if (_pTime->length >= 14 && NStr::fg_CharIsNumber(pData[12]) && NStr::fg_CharIsNumber(pData[13]))
				Seconds = (pData[12] - '0') * 10 + (pData[13] - '0');

			if (!fg_IsValidDateTime(Years, Months, Days, Hours, Minutes, Seconds))
				return NTime::CTime::fs_StartOfTime();

			return NTime::CTimeConvert::fs_CreateTime(Years, Months, Days, Hours, Minutes, Seconds);
		}

		return NTime::CTime::fs_StartOfTime();
	}

	NTime::CTime fg_GetX509ExpireTime(X509 *_pCertificate)
	{
		return fg_ConvertFromASN1Time(X509_get_notAfter(_pCertificate));
	}

	EVP_PKEY *fg_LoadPrivateKey(NContainer::CSecureByteVector const &_Data)
	{
		ERR_clear_error();

		BIO* pMemoryBio = BIO_new_mem_buf(const_cast<void*>(static_cast<void const*>(_Data.f_GetArray())), _Data.f_GetLen());
		if (!pMemoryBio)
			DMibErrorCryptography(fg_GetExceptionStr("Failed to create BIO buffer"));
		auto Cleanup0 = g_OnScopeExit / [&]
			{
				BIO_free(pMemoryBio);
			}
		;

		ERR_clear_error();
		EVP_PKEY* pKey = PEM_read_bio_PrivateKey(pMemoryBio, nullptr, nullptr, nullptr);
		if (!pKey)
			DMibErrorCryptography(fg_GetExceptionStr("Failed to read private key"));

		return pKey;
	}
}
