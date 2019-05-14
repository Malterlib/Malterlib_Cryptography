#pragma once

#include "Malterlib_Cryptography_KeyDerivation.h"
#include "Malterlib_Cryptography_Exception.h"

namespace NMib::NCryptography
{
	enum ECryptoFlags
	{
		ECryptoFlags_None = DMibBit(0)
		, ECryptoFlags_Decrypt = DMibBit(1)
		, ECryptoFlags_Encrypt = DMibBit(2)
		, ECryptoFlags_UsePadding = DMibBit(3)
	};

	class CEncryptAES
	{
	public:

		CEncryptAES(CEncryptKeyIV const &_KeyIV);
		~CEncryptAES();

		uint32 f_Encrypt(uint8 *_pSource, uint32 _SourceLen, uint8 *_pDest) const;
		uint32 f_Decrypt(uint8 *_pSource, uint32 _SourceLen, uint8 *_pDest) const;

	private:
		struct CInternal;
		NStorage::TCUniquePointer<CInternal> mp_pInternal;
	};

	// If all the data is available at once, use CEncryptAES. CIncrementalEncrypt does the same job but can operate on piecemeal data.
	//
	// When padding is used, feed the Encrypter all the data (while (!EndOfData) Encrypter.f_{De,En}crypt(Data);) and then call Encrypter.f_FinalizePadded{De,En}crypt
	// to get the final block from the Encrypter.
	class CIncrementalEncrypt
	{
	public:
		CIncrementalEncrypt(ECryptoFlags _Flags, CEncryptKeyIV const &_KeyIV);
		~CIncrementalEncrypt();

		uint32 f_Encrypt(uint8 const *_pSource, uint32 _SourceLen, uint8 *_pDest);
		uint32 f_Decrypt(uint8 const *_pSource, uint32 _SourceLen, uint8 *_pDest);
		uint32 f_FinalizePaddedEncrypt(uint8 *_pDest, uint32 _DestLen);
		uint32 f_FinalizePaddedDecrypt(uint8 *_pDest, uint32 _DestLen);

	private:
		struct CInternal;
		NStorage::TCUniquePointer<CInternal> mp_pInternal;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
