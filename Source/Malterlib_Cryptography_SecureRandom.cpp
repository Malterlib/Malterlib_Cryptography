// Copyright © 2025 Favro Holding AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include "Malterlib_Cryptography_SecureRandom.h"

#include <openssl/chacha.h>

namespace NMib::NCryptography
{
	CSecureRandom::CSecureRandom()
	{
		fp_Reseed();
	}

	CSecureRandom::~CSecureRandom()
	{
		NMemory::fg_SecureMemClear(mp_Key);
		NMemory::fg_SecureMemClear(mp_Nonce);
		NMemory::fg_SecureMemClear(mp_Buffer);
	}

	void CSecureRandom::fp_Reseed()
	{
		NSys::fg_Security_GenerateHighEntropyData(mp_Key, 32);
		NSys::fg_Security_GenerateHighEntropyData(mp_Nonce, 12);
		mp_Counter = 0;
		mp_BytesGenerated = 0;
		mp_BufferPos = mc_BlockSize;
	}

	void CSecureRandom::fp_GenerateBlock()
	{
		if (mp_BytesGenerated >= mc_ReseedThreshold)
			fp_Reseed();

		// Generate random bytes by encrypting zeros with ChaCha20
		uint8 Zeros[mc_BlockSize] = {0};
		CRYPTO_chacha_20(mp_Buffer, Zeros, mc_BlockSize, mp_Key, mp_Nonce, mp_Counter++);
		mp_BufferPos = 0;
		mp_BytesGenerated += mc_BlockSize;
	}

	void CSecureRandom::f_GetBytes(uint8 *_pOut, mint _nBytes)
	{
		while (_nBytes > 0)
		{
			if (mp_BufferPos >= mc_BlockSize)
				fp_GenerateBlock();

			mint nCopy = fg_Min(_nBytes, mc_BlockSize - mp_BufferPos);
			NMemory::fg_MemCopy(_pOut, mp_Buffer + mp_BufferPos, nCopy);
			mp_BufferPos += nCopy;
			_pOut += nCopy;
			_nBytes -= nCopy;
		}
	}
}
