// Copyright © 2025 Favro Holding AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

#include <Mib/Core/Core>

namespace NMib::NCryptography
{
	// ChaCha20-based cryptographically secure random number generator
	//
	// Seeds from OS CSPRNG (via fg_Security_GenerateHighEntropyData), then generates
	// random bytes via ChaCha20 stream cipher. Reseeds periodically for forward secrecy.
	//
	// Performance: ~3-4 cycles/byte vs ~15-50 for OS CSPRNG calls
	// Security: Cryptographically secure, suitable for tokens, keys, nonces
	struct CSecureRandom
	{
		CSecureRandom();
		~CSecureRandom();

		CSecureRandom(CSecureRandom const &) = delete;
		CSecureRandom &operator=(CSecureRandom const &) = delete;

		void f_GetBytes(uint8 *_pOut, mint _nBytes);

		// Reseed from OS CSPRNG
		void f_Reseed();

		// Reseed with a predetermined seed (for reproducible sequences, NOT cryptographically secure)
		void f_InsecureDeterministicReseed(uint64 _Seed);

		template <typename t_CInt>
		t_CInt f_GetValue()
		{
			t_CInt Return;
			f_GetBytes((uint8 *)&Return, sizeof(Return));
			return Return;
		}

	private:
		static constexpr mint mcp_BlockSize = 64;                    // ChaCha20 block size (512 bits)
		static constexpr mint mcp_ReseedThreshold = 1024 * 1024;     // Reseed every 1MB for forward secrecy

		void fp_Reseed();
		void fp_GenerateBlock();

		// Members ordered to avoid padding: buffer first (cache-line aligned), then key (32-byte aligned)
		uint8 align_cacheline mp_Buffer[mcp_BlockSize];	// ChaCha20 block cache (cache-line aligned for optimal access)
		alignas(32) uint8 mp_Key[32];					// 256-bit key from OS CSPRNG (32-byte aligned for SIMD)
		uint8 mp_Nonce[12];								// 96-bit nonce from OS CSPRNG
		uint32 mp_Counter = 0;							// Block counter
		mint mp_BufferPos = mcp_BlockSize;				// Current position in buffer (mc_BlockSize = empty)
		mint mp_BytesGenerated = 0;						// Bytes generated (in whole blocks) since last reseed, mcp_ReseedThreshold*2 = deterministic mode
	};

}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
