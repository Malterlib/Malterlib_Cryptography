// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

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
		mp_BufferPos = mcp_BlockSize;
	}

	void CSecureRandom::f_Reseed()
	{
		fp_Reseed();
	}

	void CSecureRandom::f_InsecureDeterministicReseed(uint64 _Seed)
	{
		// Derive key and nonce deterministically from the seed
		// Hash the seed across the key bytes for better distribution
		uint8 SeedBytes[sizeof(_Seed)];
		NMemory::fg_MemCopy(SeedBytes, &_Seed, sizeof(_Seed));

		// Fill key by repeating ChaCha20 over the seed material
		uint8 Zeros[32] = {0};
		uint8 SeedKey[32] = {0};
		NMemory::fg_MemCopy(SeedKey, SeedBytes, sizeof(SeedBytes));
		uint8 SeedNonce[12] = {0};
		CRYPTO_chacha_20(mp_Key, Zeros, 32, SeedKey, SeedNonce, 0);

		// Derive nonce from a second block
		uint8 NonceBlock[64] = {0};
		uint8 ZeroBlock[64] = {0};
		CRYPTO_chacha_20(NonceBlock, ZeroBlock, 64, SeedKey, SeedNonce, 1);
		NMemory::fg_MemCopy(mp_Nonce, NonceBlock, 12);

		NMemory::fg_SecureMemClear(SeedKey);
		NMemory::fg_SecureMemClear(NonceBlock);

		mp_Counter = 0;
		mp_BytesGenerated = mcp_ReseedThreshold * 2;
		mp_BufferPos = mcp_BlockSize;
	}

	void CSecureRandom::fp_GenerateBlock()
	{
		if (mp_BytesGenerated == mcp_ReseedThreshold)
			fp_Reseed();

		// Generate random bytes by encrypting zeros with ChaCha20
		uint8 Zeros[mcp_BlockSize] = {0};
		CRYPTO_chacha_20(mp_Buffer, Zeros, mcp_BlockSize, mp_Key, mp_Nonce, mp_Counter++);
		mp_BufferPos = 0;
		mp_BytesGenerated += mcp_BlockSize;
	}

	void CSecureRandom::f_GetBytes(uint8 *_pOut, umint _nBytes)
	{
		while (_nBytes > 0)
		{
			if (mp_BufferPos >= mcp_BlockSize)
				fp_GenerateBlock();

			umint nCopy = fg_Min(_nBytes, mcp_BlockSize - mp_BufferPos);
			NMemory::fg_MemCopy(_pOut, mp_Buffer + mp_BufferPos, nCopy);
			mp_BufferPos += nCopy;
			_pOut += nCopy;
			_nBytes -= nCopy;
		}
	}
}
