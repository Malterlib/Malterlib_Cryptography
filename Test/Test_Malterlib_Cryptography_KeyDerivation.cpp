// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Test/Exception>
#include <Mib/Cryptography/KeyDerivation>

#define DMibCryptographyErrorInstance(d_Description) NMib::NCryptography::CExceptionCryptography("CExceptionCryptography", d_Description, false)

using namespace NMib;
using namespace NMib::NStr;
using namespace NMib::NContainer;
using namespace NMib::NCryptography;

class CKeyDerivation_Tests : public NMib::NTest::CTest
{
public:

	void f_DoTests()
	{
		DMibTestSuite("Argon2id")
		{
			// libsodium's Argon2id v1.3 test vectors (test/default/pwhash_argon2id.c, tv and tv2), which use the first _PasswordLen bytes of the
			// password and the first 16 bytes of the salt. libsodium uses the memory in whole KiB, so the memory here is rounded down to that.
			struct CTestVector
			{
				ch8 const *m_pPassword;
				umint m_PasswordLen;
				ch8 const *m_pSalt;
				umint m_KeyLen;
				uint32 m_Iterations;
				umint m_Memory;
				ch8 const *m_pExpected;
			};

			CTestVector TestVectors[] =
			{
				{
					"a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae065577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08d"
					"a232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f58d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6"
					, 127
					, "5541fbc995d5c197ba290346d2c559dedf405cf97e5f95482143202f9e74f5c2"
					, 155
					, 5
					, 7256678
					, "18acec5d6507739f203d1f5d9f1d862f7c2cdac4f19d2bdff64487e60d969e3ced615337b9eec6ac4461c6ca07f0939741e57c24d0005c7ea171a0ee1e7348249d"
					"135b38f222e4dad7b9a033ed83f5ca27277393e316582033c74affe2566a2bea47f91f0fd9fe49ece7e1f79f3ad6e9b23e0277c8ecc4b313225748dd2a80f5679534"
					"a0700e246a79a49b3f74eb89ec6205fe1eeb941c73b1fcf1"
				}
				, {
					"e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6ed9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b60e0"
					"0cc2890277f0fd3c622115772f7048adaebed86e"
					, 86
					, "f1192dd5dc2368b9cd421338b22433455ee0a3699f9379a08b9650ea2c126f0d"
					, 250
					, 4
					, 7849083
					, "26bab5f101560e48c711da4f05e81f5a3802b7a93d5155b9cab153069cc42b8e9f910bfead747652a0708d70e4de0bada37218bd203a1201c36b42f9a269b675b1"
					"f30cfc36f35a3030e9c7f57dfba0d341a974c1886f708c3e8297efbfe411bb9d51375264bd7c70d57a8a56fc9de2c1c97c08776803ec2cd0140bba8e61dc0f4ad3d3"
					"d1a89b4b710af81bfe35a0eea193e18a6da0f5ec05542c9eefc4584458e1da715611ba09617384748bd43b9bf1f3a6df4ecd091d0875e08d6e2fd8a5c7ce08904b51"
					"60cd38167b76ec76ef2d310049055a564da23d4ebd2b87e421cc33c401e12d5cd8d936c9baf75ebdfb557d342d2858fc781da31860"
				}
				, {
					"b540beb016a5366524d4605156493f9874514a5aa58818cd0c6dfffaa9e90205f17b"
					, 34
					, "44071f6d181561670bda728d43fb79b443bb805afdebaf98622b5165e01b15fb"
					, 231
					, 1
					, 1631659
					, "7fb72409b0987f8190c3729710e98c3f80c5a8727d425fdcde7f3644d467fe973f5b5fee683bd3fce812cb9ae5e9921a2d06c2f1905e4e839692f2b934b682f11a2f"
					"e2b90482ea5dd234863516dba6f52dc0702d324ec77d860c2e181f84472bd7104fedce071ffa93c5309494ad51623d214447a7b2b1462dc7d5d55a1f6fd5b54ce024"
					"118d86f0c6489d16545aaa87b6689dad9f2fb47fda9894f8e12b87d978b483ccd4cc5fd9595cdc7a818452f915ce2f7df95ec12b1c72e3788d473441d884f9748eb1"
					"4703c21b45d82fd667b85f5b2d98c13303b3fe76285531a826b6fc0fe8e3dddecf"
				}
				, {
					"a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae065577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08d"
					"a232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f58d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6"
					, 127
					, "5541fbc995d5c197ba290346d2c559dedf405cf97e5f95482143202f9e74f5c2"
					, 155
					, 3
					, 397645
					, "8fb6ed1862cdd2a399e10956c60dc9b2670338ea59c3414d0443216925ba24c6e89a17f3e56c12893dcbc9bc498e8308aea9627d9c9e47912d6342b631008719ed"
					"fa2db364b97e60cf47a97ad9aa3b7f139d80ddda44f1ef2af881ce027a15644218cac6cc74751469ae56be0469fbc760825882b3e8abca55daaae5753575106cf867"
					"cd69932602c63ec880ad8811d9aa4870a9e0b39fef47c92e"
				}
			};

			umint iVector = 0;
			for (auto const &Vector : TestVectors)
			{
				DMibTestPath("Vector {}"_f << iVector++);

				CSecureByteVector PasswordBytes = fsp_FromHex(Vector.m_pPassword);
				CStrSecure Password;
				Password.f_AddStr((ch8 const *)PasswordBytes.f_GetArray(), Vector.m_PasswordLen);

				CSecureByteVector Salt = fsp_FromHex(Vector.m_pSalt);
				Salt.f_SetLen(16);

				CKeyDerivationSettings_Argon2id Settings;
				Settings.m_Iterations = Vector.m_Iterations;
				Settings.m_Memory = Vector.m_Memory / 1024 * 1024;

				CSecureByteVector Key = fg_DeriveKey(Password, Salt, Settings, Vector.m_KeyLen);
				DMibExpect(fsp_ToHex(Key), ==, CStr(Vector.m_pExpected));
			}
		};

		DMibTestSuite("Argon2idInvalidInput")
		{
			CStrSecure Password("password");
			CSecureByteVector Salt;
			Salt.f_SetLen(16);
			NMemory::fg_MemClear(Salt.f_GetArray(), Salt.f_GetLen());

			auto fDerive = [&](CSecureByteVector const &_Salt, CKeyDerivationSettings_Argon2id const &_Settings, umint _KeyLen)
				{
					return fg_DeriveKey(Password, _Salt, _Settings, _KeyLen);
				}
			;

			CKeyDerivationSettings_Argon2id Small;
			Small.m_Memory = 8 * 1024;
			Small.m_Iterations = 1;

			{
				DMibTestPath("Valid");
				DMibExpect(fDerive(Salt, Small, 32).f_GetLen(), ==, 32);
			}
			{
				DMibTestPath("Salt");
				CSecureByteVector ShortSalt;
				ShortSalt.f_SetLen(8);
				DMibExpectException(fDerive(ShortSalt, Small, 32), DMibCryptographyErrorInstance("Argon2id needs a salt of 16 bytes, got 8"));
			}
			{
				DMibTestPath("KeyLength");
				DMibExpectException(fDerive(Salt, Small, 15), DMibCryptographyErrorInstance("Argon2id key length must be 16 to 4294967295 bytes, got 15"));
			}
			{
				DMibTestPath("Iterations");
				auto Settings = Small;
				Settings.m_Iterations = 0;
				DMibExpectException(fDerive(Salt, Settings, 32), DMibCryptographyErrorInstance("Argon2id iterations must be at least 1, got 0"));
			}
			{
				DMibTestPath("MemoryNotWholeKiB");
				auto Settings = Small;
				Settings.m_Memory = 8 * 1024 + 1;
				DMibExpectException(fDerive(Salt, Settings, 32), DMibCryptographyErrorInstance("Argon2id memory must be a multiple of 1024 bytes, got 8193"));
			}
			{
				DMibTestPath("MemoryTooSmall");
				auto Settings = Small;
				Settings.m_Memory = 4 * 1024;
				// libsodium's maximum depends on the address size
				umint MaxMemory = sizeof(void *) >= 8 ? umint(4398046510080) : umint(2147483648);
				DMibExpectException
					(
						fDerive(Salt, Settings, 32)
						, DMibCryptographyErrorInstance("Argon2id memory must be 8192 to {} bytes, got 4096"_f << MaxMemory)
					)
				;
			}
			{
				DMibTestPath("MemoryAboveMax");
				auto Settings = Small;
				Settings.m_Memory = 16 * 1024;
				Settings.m_MaxMemory = 8 * 1024;
				DMibExpectException(fDerive(Salt, Settings, 32), DMibCryptographyErrorInstance("Argon2id memory 16384 is more than the allowed 8192 bytes"));
			}
		};
	}

private:

	static CSecureByteVector fsp_FromHex(ch8 const *_pHex)
	{
		auto fDigit = [](ch8 _Character) -> uint8
			{
				if (_Character >= '0' && _Character <= '9')
					return _Character - '0';
				return _Character - 'a' + 10;
			}
		;

		CSecureByteVector Bytes;
		umint Len = fg_StrLen(_pHex);
		for (umint i = 0; i + 1 < Len; i += 2)
			Bytes.f_Insert(uint8((fDigit(_pHex[i]) << 4) | fDigit(_pHex[i + 1])));
		return Bytes;
	}

	static CStr fsp_ToHex(CSecureByteVector const &_Bytes)
	{
		CStr Hex;
		for (auto Byte : _Bytes)
			Hex += "{nfh,sj2,sf0}"_f << Byte;
		return Hex;
	}
};

DMibTestRegister(CKeyDerivation_Tests, Malterlib::Cryptography);
