#include "Malterlib_Cryptography_SymmetricCrypto.h"

#include <Mib/Cryptography/BoringSSL>

namespace NMib::NCryptography
{
	using namespace NBoringSSL;

	struct CEncryptAES::CInternal
	{
		CInternal(CEncryptKeyIV const &_KeyIV)
		{
			fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						DMibCheck(_KeyIV.m_Key.f_GetLen() == 32);
						DMibCheck(_KeyIV.m_IV.f_GetLen() == 16);
						NMemory::fg_MemCopy(m_Key, _KeyIV.m_Key.f_GetArray(), fg_Min(_KeyIV.m_Key.f_GetLen(), (mint)EVP_MAX_KEY_LENGTH));
						NMemory::fg_MemCopy(m_IV, _KeyIV.m_IV.f_GetArray(), fg_Min(_KeyIV.m_IV.f_GetLen(), (mint)EVP_MAX_IV_LENGTH));
					}
				)
			;
		}

		~CInternal()
		{
			NMemory::fg_SecureMemClear(m_Key, EVP_MAX_KEY_LENGTH);
			NMemory::fg_SecureMemClear(m_IV, EVP_MAX_IV_LENGTH);
		}

		uint32 f_Encrypt(uint8 *_pSource, uint32 _SourceLen, uint8 *_pDest) const
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						EVP_CIPHER_CTX *pCipherContext = nullptr;
						auto Cleanup = g_OnScopeExit / [&]
							{
								EVP_CIPHER_CTX_free(pCipherContext);
							}
						;

						ERR_clear_error();
						if (!(pCipherContext = EVP_CIPHER_CTX_new()))
							DMibErrorCryptography(fg_GetExceptionStr("Failed to create cipher context"));

						ERR_clear_error();
						if (EVP_EncryptInit_ex(pCipherContext, EVP_aes_256_cbc(), nullptr, m_Key, m_IV) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Failed to initialize cipher context"));

						ERR_clear_error();
						EVP_CIPHER_CTX_set_padding(pCipherContext, 0);

						int EncryptedLen = 0;
						ERR_clear_error();
						if (EVP_EncryptUpdate(pCipherContext, _pDest, &EncryptedLen, _pSource, (int)_SourceLen) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Failed to encrypt data"));

						int FinalizeLen = 0;
						ERR_clear_error();
						if (EVP_EncryptFinal_ex(pCipherContext, _pDest + EncryptedLen, &FinalizeLen) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Failed to finalize encrypted data"));

						return uint32(EncryptedLen + FinalizeLen);
					}
				)
			;
		}

		uint32 f_Decrypt(uint8 *_pSource, uint32 _SourceLen, uint8 *_pDest) const
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						EVP_CIPHER_CTX *pCipherContext = nullptr;
						auto Cleanup = g_OnScopeExit / [&]
							{
								EVP_CIPHER_CTX_free(pCipherContext);
							}
						;

						ERR_clear_error();
						if (!(pCipherContext = EVP_CIPHER_CTX_new()))
							DMibErrorCryptography(fg_GetExceptionStr("Failed to create cipher context"));

						ERR_clear_error();
						if (EVP_DecryptInit_ex(pCipherContext, EVP_aes_256_cbc(), nullptr, m_Key, m_IV) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Failed to initialize cipher context"));

						ERR_clear_error();
						EVP_CIPHER_CTX_set_padding(pCipherContext, 0);

						int DecryptedLen = 0;
						ERR_clear_error();
						if (EVP_DecryptUpdate(pCipherContext, _pDest, &DecryptedLen, _pSource, (int)_SourceLen) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Failed to decrypt"));

						int FinalLen = 0;
						ERR_clear_error();
						if (EVP_DecryptFinal_ex(pCipherContext, _pDest + DecryptedLen, &FinalLen) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Failed to finalize decryption"));

						return uint32(DecryptedLen + FinalLen);
					}
				)
			;
		}

		uint8 m_Key[EVP_MAX_KEY_LENGTH];
		uint8 m_IV[EVP_MAX_IV_LENGTH];
	};

	CEncryptAES::CEncryptAES(CEncryptKeyIV const &_KeyIV)
		: mp_pInternal(fg_Construct(_KeyIV))
	{
	}

	CEncryptAES::~CEncryptAES()
	{
	}

	uint32 CEncryptAES::f_Encrypt(uint8 *_pSource, uint32 _SourceLen, uint8 *_pDest) const
	{
		return mp_pInternal->f_Encrypt(_pSource, _SourceLen, _pDest);
	}

	uint32 CEncryptAES::f_Decrypt(uint8 *_pSource, uint32 _SourceLen, uint8 *_pDest) const
	{
		return mp_pInternal->f_Decrypt(_pSource, _SourceLen, _pDest);
	}

	struct CIncrementalEncrypt::CInternal
	{
		CInternal(ECryptoFlags _Flags, CEncryptKeyIV const &_KeyIV)
		{
			EVP_CIPHER const *pCipher = fg_GetCipher(_KeyIV.m_Crypto);
			if (_KeyIV.m_Key.f_GetLen() < EVP_CIPHER_key_length(pCipher))
				DMibErrorCryptography(NStr::fg_Format("Key too short. Must be at least {} bytes", EVP_CIPHER_key_length(pCipher)));

			if (_KeyIV.m_IV.f_GetLen() < EVP_CIPHER_iv_length(pCipher))
				DMibErrorCryptography(NStr::fg_Format("IV too short. Must be at least {} bytes", EVP_CIPHER_iv_length(pCipher)));

			fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						if ((_Flags & (ECryptoFlags_Encrypt | ECryptoFlags_Decrypt)) == (ECryptoFlags_Encrypt | ECryptoFlags_Decrypt))
							DMibErrorCryptography("Cannot handle both ECryptoFlags_Encrypt and ECryptoFlags_Decrypt");

						ERR_clear_error();
						if (!(m_pCipherContext = EVP_CIPHER_CTX_new()))
							DMibErrorCryptography(fg_GetExceptionStr("Failed to create cipher context"));

						auto Cleanup = g_OnScopeExit / [&]
							{
								this->~CInternal();
							}
						;

						ERR_clear_error();
						if (_Flags & ECryptoFlags_Encrypt)
						{
							if (EVP_EncryptInit_ex(m_pCipherContext, pCipher, nullptr, _KeyIV.m_Key.f_GetArray(), _KeyIV.m_IV.f_GetArray()) != 1)
								DMibErrorCryptography(fg_GetExceptionStr("Failed to initialize cipher context"));
						}
						else if (_Flags & ECryptoFlags_Decrypt)
						{
							if (EVP_DecryptInit_ex(m_pCipherContext, pCipher, nullptr, _KeyIV.m_Key.f_GetArray(), _KeyIV.m_IV.f_GetArray()) != 1)
								DMibErrorCryptography(fg_GetExceptionStr("Failed to initialize cipher context"));
						}
						else
							DMibErrorCryptography("Must specify either ECryptoFlags_Encrypt or ECryptoFlags_Decrypt");

						ERR_clear_error();
						if (_Flags & ECryptoFlags_UsePadding)
							EVP_CIPHER_CTX_set_padding(m_pCipherContext, 1);
						else
							EVP_CIPHER_CTX_set_padding(m_pCipherContext, 0);

						Cleanup.f_Clear();
					}
				)
			;
		}

		~CInternal()
		{
			EVP_CIPHER_CTX_free(m_pCipherContext);
		}

		uint32 f_Encrypt(uint8 const *_pSource, uint32 _SourceLen, uint8 *_pDest) const
		{
			if (!m_pCipherContext)
				DMibErrorCryptography("No encryption context. Please initialize before calling f_Encrypt.");

			DMibRequire(m_pCipherContext->encrypt);

			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						int EncryptedLen = 0;
						ERR_clear_error();
						if (EVP_EncryptUpdate(m_pCipherContext, _pDest, &EncryptedLen, _pSource, (int)_SourceLen) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Failed to encrypt data"));

						return EncryptedLen;
					}
				)
			;
		}

		uint32 f_Decrypt(uint8 const *_pSource, uint32 _SourceLen, uint8 *_pDest) const
		{
			if (!m_pCipherContext)
				DMibErrorCryptography("No encryption context. Please initialize before calling f_Decrypt.");

			DMibRequire(!m_pCipherContext->encrypt);

			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						int DecryptedLen = 0;
						ERR_clear_error();
						if (EVP_DecryptUpdate(m_pCipherContext, _pDest, &DecryptedLen, _pSource, (int)_SourceLen) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Failed to decrypt"));

						return DecryptedLen;
					}
				)
			;
		}

		uint32 f_FinalizePaddedEncrypt(uint8 *_pDest, uint32 _DestLen)
		{
			if (!m_pCipherContext)
				DMibErrorCryptography("No encryption context. Please initialize before calling f_FinalizeEncrypt.");

			auto nNeededBytes = EVP_CIPHER_CTX_block_size(m_pCipherContext);
			if (_DestLen < nNeededBytes)
				DMibErrorCryptography(NStr::fg_Format("Buffer is too short. Need at least {} bytes",  nNeededBytes));

			DMibRequire(m_pCipherContext->encrypt);

			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						int FinalizeLen = 0;
						ERR_clear_error();
						if (EVP_EncryptFinal_ex(m_pCipherContext, _pDest, &FinalizeLen) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Failed to finalize encrypted data"));

						return FinalizeLen;
					}
				)
			;
		}

		uint32 f_FinalizePaddedDecrypt(uint8 *_pDest, uint32 _DestLen)
		{
			if (!m_pCipherContext)
				DMibErrorCryptography("No encryption context. Please initialize before calling f_FinalizeDecrypt.");

			auto nNeededBytes = EVP_CIPHER_CTX_block_size(m_pCipherContext);
			if (_DestLen < nNeededBytes)
				DMibErrorCryptography(NStr::fg_Format("Buffer is too short. Need at least {} bytes",  nNeededBytes));

			DMibRequire(!m_pCipherContext->encrypt);

			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						int FinalizeLen = 0;
						ERR_clear_error();
						if (EVP_DecryptFinal_ex(m_pCipherContext, _pDest, &FinalizeLen) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Failed to finalize decryption"));

						return FinalizeLen;
					}
				)
			;
		}

		EVP_CIPHER_CTX *m_pCipherContext = nullptr;
	};

	CIncrementalEncrypt::CIncrementalEncrypt(ECryptoFlags _Flags, CEncryptKeyIV const &_KeyIV)
		: mp_pInternal(fg_Construct(_Flags, _KeyIV))
	{
	}

	CIncrementalEncrypt::~CIncrementalEncrypt()
	{
	}

	uint32 CIncrementalEncrypt::f_Encrypt(uint8 const *_pSource, uint32 _SourceLen, uint8 *_pDest)
	{
		return mp_pInternal->f_Encrypt(_pSource, _SourceLen, _pDest);
	}

	uint32 CIncrementalEncrypt::f_Decrypt(uint8 const *_pSource, uint32 _SourceLen, uint8 *_pDest)
	{
		return mp_pInternal->f_Decrypt(_pSource, _SourceLen, _pDest);
	}

	uint32 CIncrementalEncrypt::f_FinalizePaddedEncrypt(uint8 *_pDest, uint32 _DestLen)
	{
		return mp_pInternal->f_FinalizePaddedEncrypt(_pDest, _DestLen);
	}

	uint32 CIncrementalEncrypt::f_FinalizePaddedDecrypt(uint8 *_pDest, uint32 _DestLen)
	{
		return mp_pInternal->f_FinalizePaddedDecrypt(_pDest, _DestLen);
	}	
}
