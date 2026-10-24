// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Cryptography_KeyDerivation_Argon2id.h"

#include <stdlib.h>

#define SODIUM_STATIC 1
#include "../../../External/libsodium/src/libsodium/include/sodium/core.h"
#include "../../../External/libsodium/src/libsodium/include/sodium/crypto_pwhash_argon2id.h"
#include "../../../External/libsodium/src/libsodium/include/sodium/randombytes.h"
#include "../../../External/libsodium/src/libsodium/include/sodium/runtime.h"

// Only the Argon2id parts of libsodium are built, so this file provides the rest of what they need.
extern "C"
{
	int _crypto_generichash_blake2b_pick_best_implementation(void);
	int _crypto_pwhash_argon2_pick_best_implementation(void);

	void randombytes_buf(void * const _pBuffer, size_t const _Size)
	{
		NMib::NSys::fg_Security_GenerateHighEntropyData((uint8 *)_pBuffer, _Size);
	}

	void sodium_misuse(void)
	{
		::abort();
	}
}

namespace NMib::NCryptography::NPrivate
{
	using namespace NStr;

	namespace
	{
		struct CSubSystem_Cryptography_Sodium : public CSubSystem
		{
			CSubSystem_Cryptography_Sodium()
			{
				_sodium_runtime_get_cpu_features();
				_crypto_generichash_blake2b_pick_best_implementation();
				_crypto_pwhash_argon2_pick_best_implementation();
			}
		};

		constinit TCSubSystem<CSubSystem_Cryptography_Sodium, ESubSystemDestruction_BeforeMemoryManager> g_SubSystem_Cryptography_Sodium = {DAggregateInit};
	}

	void fg_DeriveKeyArgon2id
		(
			NStr::CStrSecure const &_Password
			, NContainer::CSecureByteVector const &_PasswordSalt
			, CKeyDerivationSettings_Argon2id const &_Settings
			, NContainer::CSecureByteVector &o_Key
		)
	{
		if (_PasswordSalt.f_GetLen() != crypto_pwhash_argon2id_SALTBYTES)
			DMibErrorCryptography("Argon2id needs a salt of {} bytes, got {}"_f << crypto_pwhash_argon2id_SALTBYTES << _PasswordSalt.f_GetLen());

		if (o_Key.f_GetLen() < crypto_pwhash_argon2id_BYTES_MIN || uint64(o_Key.f_GetLen()) > uint64(crypto_pwhash_argon2id_BYTES_MAX))
		{
			DMibErrorCryptography
				(
					"Argon2id key length must be {} to {} bytes, got {}"_f << crypto_pwhash_argon2id_BYTES_MIN << crypto_pwhash_argon2id_BYTES_MAX << o_Key.f_GetLen()
				)
			;
		}

		if (uint64(_Password.f_GetLen()) > uint64(crypto_pwhash_argon2id_PASSWD_MAX))
			DMibErrorCryptography("Argon2id password is too long");

		// The maximum (crypto_pwhash_argon2id_OPSLIMIT_MAX) is the largest uint32
		if (_Settings.m_Iterations < crypto_pwhash_argon2id_OPSLIMIT_MIN)
			DMibErrorCryptography("Argon2id iterations must be at least {}, got {}"_f << crypto_pwhash_argon2id_OPSLIMIT_MIN << _Settings.m_Iterations);

		// libsodium takes the memory in bytes but uses whole KiB, so other values would silently be rounded down
		if (_Settings.m_Memory % 1024 != 0)
			DMibErrorCryptography("Argon2id memory must be a multiple of 1024 bytes, got {}"_f << _Settings.m_Memory);

		if (_Settings.m_Memory < crypto_pwhash_argon2id_MEMLIMIT_MIN || _Settings.m_Memory > crypto_pwhash_argon2id_MEMLIMIT_MAX)
		{
			DMibErrorCryptography
				(
					"Argon2id memory must be {} to {} bytes, got {}"_f
					<< crypto_pwhash_argon2id_MEMLIMIT_MIN
					<< umint(crypto_pwhash_argon2id_MEMLIMIT_MAX)
					<< _Settings.m_Memory
				)
			;
		}

		if (_Settings.m_Memory > _Settings.m_MaxMemory)
			DMibErrorCryptography("Argon2id memory {} is more than the allowed {} bytes"_f << _Settings.m_Memory << _Settings.m_MaxMemory);

		*g_SubSystem_Cryptography_Sodium;

		// The algorithm is selected explicitly, so a change of libsodium's default can't change derived keys
		if
			(
				crypto_pwhash_argon2id
				(
					o_Key.f_GetArray()
					, o_Key.f_GetLen()
					, _Password.f_GetStr()
					, _Password.f_GetLen()
					, _PasswordSalt.f_GetArray()
					, _Settings.m_Iterations
					, _Settings.m_Memory
					, crypto_pwhash_argon2id_ALG_ARGON2ID13
				)
				!= 0
			)
		{
			DMibErrorCryptography("Failed to generate key using Argon2id (out of memory?)");
		}
	}
}
