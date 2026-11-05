// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Cryptography/Hashes/SHA>
#include <Mib/Cryptography/Hashes/MD5>

namespace
{
	using namespace NMib::NContainer;
	using namespace NMib::NMisc;
	using namespace NMib;

	template <typename t_CHash, ch8 const t_pName[], ch8 const *t_pTests[], ch8 const *t_pTestDigests[], umint t_pTestRepeat[], umint t_nTests>
	struct TCTestHash : public NMib::NTest::CTest
	{
		void f_DoTests();
	};

	template <typename t_CHash, ch8 const t_pName[], ch8 const *t_pTests[], ch8 const *t_pTestDigests[], umint t_pTestRepeat[], umint t_nTests>
	void TCTestHash<t_CHash, t_pName, t_pTests, t_pTestDigests, t_pTestRepeat, t_nTests>::f_DoTests()
	{
		DMibTestSuite("Digest")
		{
			using CHash = t_CHash;
			using CHashDigest = typename t_CHash::CMessageDigest;

			CHash Hash;
			CHashDigest Digest;

			for (umint iTest = 0; iTest < t_nTests; ++iTest)
			{
				Hash.f_Reset();
				umint Len = NMib::NStr::fg_StrLen(t_pTests[iTest]);
				for (umint iRepeat = 0; iRepeat < t_pTestRepeat[iTest]; ++iRepeat)
					Hash.f_AddData(t_pTests[iTest], Len);

				Digest = CHashDigest(Hash);
				NMib::NStr::CStr DigestString = Digest.f_GetString().f_LowerCase();
				DMibExpect(DigestString, ==, t_pTestDigests[iTest])(ETestFlag_Aggregated);
			}
#if 0
			{
				int TestSize = 64; // 512 MB creation test

				TCVector<uint8> Data;
				Data.f_SetLen(TestSize);

				for (int i = 0; i < TestSize / 4; ++i)
					Data[i] = fg_GetRandomUnsigned();

				int nTests = 256 * 1024;

				NMib::NTime::CPerfTimeMeasureMin TimerAlloc;

				CHashDigest Digest2;

				{
					DMibScopePerfTimeMeasureMin(TimerAlloc);
					for (int i = 0; i < nTests; ++i)
					{
						CHash Hash;
						Hash.f_AddData(Data.f_GetArray(), TestSize);
						Digest2 = fg_Move(Hash).f_GetDigest();
					}
				}
				DMibTrace("Malterlib{}: {}\n", t_pName, Digest2.f_GetString());

				fp64 MiBSec = (fp64(TestSize*nTests) / TimerAlloc.f_GetTime()) / (1024.0 * 1024.0);
				fp64 DigestsSec = (fp64(nTests) / TimerAlloc.f_GetTime());

				DMibTrace("Malterlib{} of {} digests in {} seconds: Performance {} digests/second {} MiB/second\n", t_pName, nTests, TimerAlloc.f_GetTime(), DigestsSec, MiBSec);
			}
			{
				int TestSize = 64; // 512 MB creation test

				TCVector<uint8> Data;
				Data.f_SetLen(TestSize);

				for (int i = 0; i < TestSize / 4; ++i)
					Data[i] = fg_GetRandomUnsigned();

				int nTests = 256 * 1024;

				NMib::NTime::CPerfTimeMeasureMin TimerAlloc;

				CHashDigest Digest2;

				{
					CHash Hash;
					DMibScopePerfTimeMeasureMin(TimerAlloc);
					for (int i = 0; i < nTests; ++i)
					{
						Hash.f_Reset();
						Hash.f_AddData(Data.f_GetArray(), TestSize);
						Digest2 = fg_Move(Hash).f_GetDigest();
					}
				}
				DMibTrace("Malterlib{}: {}\n", t_pName, Digest2.f_GetString());

				fp64 MiBSec = (fp64(TestSize*nTests) / TimerAlloc.f_GetTime()) / (1024.0 * 1024.0);
				fp64 DigestsSec = (fp64(nTests) / TimerAlloc.f_GetTime());

				DMibTrace("Reset Malterlib{} of {} digests in {} seconds: Performance {} digests/second {} MiB/second\n", t_pName, nTests, TimerAlloc.f_GetTime(), DigestsSec, MiBSec);
			}

			{
				int TestSize = 512 * 1024 * 1024; // 512 MB creation test

				TCVector<uint8> Data;
				Data.f_SetLen(TestSize);

				for (int i = 0; i < TestSize / 4; ++i)
					Data[i] = fg_GetRandomUnsigned();

				int nTests = 1;

				NMib::NTime::CPerfTimeMeasureMin TimerAlloc;
				CHashDigest Digest2;

				{
					DMibScopePerfTimeMeasureMin(TimerAlloc);
					Hash.f_Reset();
					for (int i = 0; i < nTests; ++i)
						Hash.f_AddData(Data.f_GetArray(), TestSize);
					Digest2 = Hash;
				}
				DMibTrace("Malterlib{}: {}\n", t_pName, Digest2.f_GetString());

				fp64 MiBSec = (fp64(TestSize*nTests) / TimerAlloc.f_GetTime()) / (1024.0 * 1024.0);

				DMibTrace("Malterlib{} of {} MiB of data in {} seconds: Performance {} MiB/second\n", t_pName, (TestSize*nTests) / (1024 * 1024), TimerAlloc.f_GetTime(), MiBSec);
			}

			{
				int TestSize = 4 * 1024; // L1 cache test

				TCVector<uint8> Data;
				Data.f_SetLen(TestSize);

				for (int i = 0; i < TestSize / 4; ++i)
					Data[i] = fg_GetRandomUnsigned();

				// Add to cache
				Hash.f_Reset();
				Hash.f_AddData(Data.f_GetArray(), TestSize);
				int nTests = 128 * 1024;

				NMib::NTime::CPerfTimeMeasureMin TimerAlloc;
				CHashDigest Digest2;

				{
					DMibScopePerfTimeMeasureMin(TimerAlloc);
					Hash.f_Reset();
					for (int i = 0; i < nTests; ++i)
						Hash.f_AddData(Data.f_GetArray(), TestSize);
					Digest2 = Hash;
				}
				DMibTrace("Malterlib{}: {}\n", t_pName, Digest2.f_GetString());

				fp64 MiBSec = (fp64(TestSize*nTests) / TimerAlloc.f_GetTime()) / (1024.0 * 1024.0);

				DMibTrace("Malterlib{} of {} MiB of cached data in {} seconds: Performance {} MiB/second\n", t_pName, (TestSize*nTests) / (1024 * 1024), TimerAlloc.f_GetTime(), MiBSec);
			}
#endif
		};
	}

	extern ch8 const g_NameMD5[];
	extern ch8 const *g_TestsMD5[];
	extern ch8 const *g_TestsDigestsMD5[];
	extern umint g_TestRepeatMD5[];

	ch8 const g_NameMD5[] = "MD5";
	ch8 const *g_TestsMD5[] =
		{
			""
			, "a"
			, "abc"
			, "message digest"
			, "abcdefghijklmnopqrstuvwxyz"
			, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
			, "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
		}
	;
	ch8 const *g_TestsDigestsMD5[] =
		{
			"d41d8cd98f00b204e9800998ecf8427e"
			, "0cc175b9c0f1b6a831c399e269772661"
			, "900150983cd24fb0d6963f7d28e17f72"
			, "f96b697d7cb7938d525a2f31aaf161d0"
			, "c3fcd3d76192e4007dfb496cca67e13b"
			, "d174ab98d277d9f5a5611c2c9f419d9f"
			, "57edf4a22be3c955ac49da2e2107b67a"
		}
	;
	umint g_TestRepeatMD5[] = {1, 1, 1, 1, 1, 1, 1};

	using CDigestMD5_Tests = TCTestHash<NMib::NCryptography::CHash_MD5, g_NameMD5, g_TestsMD5, g_TestsDigestsMD5, g_TestRepeatMD5, fg_ArraySize(g_TestsMD5)>;
	DMibTestRegister(CDigestMD5_Tests, Malterlib::Cryptography);

	extern ch8 const g_NameSHA1[];
	extern ch8 const *g_TestsSHA1[];
	extern ch8 const *g_TestsDigestsSHA1[];
	extern umint g_TestRepeatSHA1[];

	ch8 const g_NameSHA1[] = "SHA1";
	ch8 const *g_TestsSHA1[] =
		{
			"abc"
			, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
			, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}
	;
	ch8 const *g_TestsDigestsSHA1[] =
		{
			"a9993e364706816aba3e25717850c26c9cd0d89d"
			, "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
			, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
		}
	;
	umint g_TestRepeatSHA1[] = {1, 1, 15625};

	using CDigestSHA1_Tests = TCTestHash<NMib::NCryptography::CHash_SHA1, g_NameSHA1, g_TestsSHA1, g_TestsDigestsSHA1, g_TestRepeatSHA1, fg_ArraySize(g_TestsSHA1)>;
	DMibTestRegister(CDigestSHA1_Tests, Malterlib::Cryptography);

	extern ch8 const g_NameSHA256[];
	extern ch8 const *g_TestsSHA256[];
	extern ch8 const *g_TestsDigestsSHA256[];
	extern umint g_TestRepeatSHA256[];

	ch8 const g_NameSHA256[] = "SHA256";
	ch8 const *g_TestsSHA256[] =
		{
			"abc"
			, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
		}
	;
	ch8 const *g_TestsDigestsSHA256[] =
		{
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
			, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
		}
	;
	umint g_TestRepeatSHA256[] = {1, 1};

	using CDigestSHA256_Tests = TCTestHash<NMib::NCryptography::CHash_SHA256, g_NameSHA256, g_TestsSHA256, g_TestsDigestsSHA256, g_TestRepeatSHA256, fg_ArraySize(g_TestsSHA256)>;
	DMibTestRegister(CDigestSHA256_Tests, Malterlib::Cryptography);

	extern ch8 const g_NameSHA384[];
	extern ch8 const *g_TestsSHA384[];
	extern ch8 const *g_TestsDigestsSHA384[];
	extern umint g_TestRepeatSHA384[];

	ch8 const g_NameSHA384[] = "SHA384";
	ch8 const *g_TestsSHA384[] =
		{
			"abc"
			, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
		}
	;
	ch8 const *g_TestsDigestsSHA384[] =
		{
			"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
			, "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
		}
	;
	umint g_TestRepeatSHA384[] = {1, 1};

	using CDigestSHA384_Tests = TCTestHash<NMib::NCryptography::CHash_SHA384, g_NameSHA384, g_TestsSHA384, g_TestsDigestsSHA384, g_TestRepeatSHA384, fg_ArraySize(g_TestsSHA384)>;
	DMibTestRegister(CDigestSHA384_Tests, Malterlib::Cryptography);

	extern ch8 const g_NameSHA512[];
	extern ch8 const *g_TestsSHA512[];
	extern ch8 const *g_TestsDigestsSHA512[];
	extern umint g_TestRepeatSHA512[];

	ch8 const g_NameSHA512[] = "SHA512";
	ch8 const *g_TestsSHA512[] =
		{
			"abc"
			, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
		}
	;
	ch8 const *g_TestsDigestsSHA512[] =
		{
			"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
			, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
		}
	;
	umint g_TestRepeatSHA512[] = {1, 1};

	using CDigestSHA512_Tests = TCTestHash<NMib::NCryptography::CHash_SHA512, g_NameSHA512, g_TestsSHA512, g_TestsDigestsSHA512, g_TestRepeatSHA512, fg_ArraySize(g_TestsSHA512)>;
	DMibTestRegister(CDigestSHA512_Tests, Malterlib::Cryptography);
}
