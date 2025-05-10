// Copyright © 2015 Hansoft AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Cryptography/Hashes/SHA>
#include <Mib/Cryptography/Hashes/MD5>

namespace
{
	using namespace NMib::NContainer;
	using namespace NMib::NMisc;
	using namespace NMib;

	template <typename t_CHash, const ch8 t_pName[], const ch8 *t_pTests[], const ch8 *t_pTestDigests[], mint t_pTestRepeat[], mint t_nTests>
	class TCTestHash : public NMib::NTest::CTest
	{
	public:
		void f_DoTests()
		{
			DMibTestSuite("Digest")
			{
				typedef t_CHash CHash;
				typedef typename t_CHash::CMessageDigest CHashDigest;
				CHash Hash;
				CHashDigest Digest;

				for (mint i = 0; i < t_nTests; ++i)
				{
					Hash.f_Reset();
					mint Len = NMib::NStr::fg_StrLen(t_pTests[i]);
					for (mint j = 0; j < t_pTestRepeat[i]; ++j)
						Hash.f_AddData(t_pTests[i], Len);

					Digest = CHashDigest(Hash);
					NMib::NStr::CStr DigestString = Digest.f_GetString().f_LowerCase();
					DMibExpect(DigestString, ==, t_pTestDigests[i])(ETestFlag_Aggregated);
				}
#if 0
				{
					int TestSize = 64; // 512 MB creation test

					TCVector<uint8> Data;
					Data.f_SetLen(TestSize);

					for (int i = 0; i < TestSize / 4; ++i)
						Data[i] = fg_GetRandomUnsigned();

					int nTests = 256 * 1024;

					NMib::NTime::CTimerMin TimerAlloc;

					CHashDigest Digest2;

					{
						DMibScopeTimerMin(TimerAlloc);
						for (int i = 0; i < nTests; ++i)
						{
							CHash Hash;
							Hash.f_AddData(Data.f_GetArray(), TestSize);
							Digest2 = fg_Move(Hash).f_GetDigest();
						}
					}
					DMibTrace("Malterlib{}: {}\n", t_pName << Digest2.f_GetString());

					fp64 MiBSec = (fp64(TestSize*nTests) / TimerAlloc.f_GetTime()) / (1024.0 * 1024.0);
					fp64 DigestsSec = (fp64(nTests) / TimerAlloc.f_GetTime());

					DMibTrace("Malterlib{} of {} digests in {} seconds: Performance {} digests/second {} MiB/second\n", t_pName << nTests << TimerAlloc.f_GetTime() << DigestsSec << MiBSec);
				}
				{
					int TestSize = 64; // 512 MB creation test

					TCVector<uint8> Data;
					Data.f_SetLen(TestSize);

					for (int i = 0; i < TestSize / 4; ++i)
						Data[i] = fg_GetRandomUnsigned();

					int nTests = 256 * 1024;

					NMib::NTime::CTimerMin TimerAlloc;

					CHashDigest Digest2;

					{
						CHash Hash;
						DMibScopeTimerMin(TimerAlloc);
						for (int i = 0; i < nTests; ++i)
						{
							Hash.f_Reset();
							Hash.f_AddData(Data.f_GetArray(), TestSize);
							Digest2 = fg_Move(Hash).f_GetDigest();
						}
					}
					DMibTrace("Malterlib{}: {}\n", t_pName << Digest2.f_GetString());

					fp64 MiBSec = (fp64(TestSize*nTests) / TimerAlloc.f_GetTime()) / (1024.0 * 1024.0);
					fp64 DigestsSec = (fp64(nTests) / TimerAlloc.f_GetTime());

					DMibTrace("Reset Malterlib{} of {} digests in {} seconds: Performance {} digests/second {} MiB/second\n", t_pName << nTests << TimerAlloc.f_GetTime() << DigestsSec << MiBSec);
				}

				{
					int TestSize = 512*1024*1024; // 512 MB creation test

					TCVector<uint8> Data;
					Data.f_SetLen(TestSize);

					for (int i = 0; i < TestSize / 4; ++i)
						Data[i] = fg_GetRandomUnsigned();

					int nTests = 1;

					NMib::NTime::CTimerMin TimerAlloc;
					CHashDigest Digest2;

					{
						DMibScopeTimerMin(TimerAlloc);
						Hash.f_Reset();
						for (int i = 0; i < nTests; ++i)
							Hash.f_AddData(Data.f_GetArray(), TestSize);
						Digest2 = Hash;
					}
					DMibTrace("Malterlib{}: {}\n", t_pName << Digest2.f_GetString());

					fp64 MiBSec = (fp64(TestSize*nTests) / TimerAlloc.f_GetTime()) / (1024.0 * 1024.0);

					DMibTrace("Malterlib{} of {} MiB of data in {} seconds: Performance {} MiB/second\n", t_pName << (TestSize*nTests)/(1024*1024) << TimerAlloc.f_GetTime() << MiBSec);
				}

				{
					int TestSize = 4*1024; // L1 cache test

					TCVector<uint8> Data;
					Data.f_SetLen(TestSize);

					for (int i = 0; i < TestSize / 4; ++i)
						Data[i] = fg_GetRandomUnsigned();

					// Add to cache
					Hash.f_Reset();
					Hash.f_AddData(Data.f_GetArray(), TestSize);
					int nTests = 128 * 1024;

					NMib::NTime::CTimerMin TimerAlloc;
					CHashDigest Digest2;

					{
						DMibScopeTimerMin(TimerAlloc);
						Hash.f_Reset();
						for (int i = 0; i < nTests; ++i)
							Hash.f_AddData(Data.f_GetArray(), TestSize);
						Digest2 = Hash;
					}
					DMibTrace("Malterlib{}: {}\n", t_pName << Digest2.f_GetString());

					fp64 MiBSec = (fp64(TestSize*nTests) / TimerAlloc.f_GetTime()) / (1024.0 * 1024.0);

					DMibTrace("Malterlib{} of {} MiB of cached data in {} seconds: Performance {} MiB/second\n", t_pName << (TestSize*nTests)/(1024*1024) << TimerAlloc.f_GetTime() << MiBSec);
				}
#endif
			};
		}
	};

	extern const ch8 g_pNameMD5[];
	extern const ch8 *g_pTestsMD5[];
	extern const ch8 *g_pTestsDigestsMD5[];
	extern mint g_pTestRepeatMD5[];

	const ch8 g_pNameMD5[] = "MD5";
	const ch8 *g_pTestsMD5[] = {
		"",
		"a",
		"abc",
		"message digest",
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
	};
	const ch8 *g_pTestsDigestsMD5[] = {
		"d41d8cd98f00b204e9800998ecf8427e",
		"0cc175b9c0f1b6a831c399e269772661",
		"900150983cd24fb0d6963f7d28e17f72",
		"f96b697d7cb7938d525a2f31aaf161d0",
		"c3fcd3d76192e4007dfb496cca67e13b",
		"d174ab98d277d9f5a5611c2c9f419d9f",
		"57edf4a22be3c955ac49da2e2107b67a",
	};
	mint g_pTestRepeatMD5[] = {1,1,1,1,1,1,1};

	typedef TCTestHash<NMib::NCryptography::CHash_MD5, g_pNameMD5, g_pTestsMD5, g_pTestsDigestsMD5, g_pTestRepeatMD5, fg_ArraySize(g_pTestsMD5)> CDigestMD5_Tests;
	DMibTestRegister(CDigestMD5_Tests, Malterlib::Crytpography);

	extern const ch8 g_pNameSHA1[];
	extern const ch8 *g_pTestsSHA1[];
	extern const ch8 *g_pTestsDigestsSHA1[];
	extern mint g_pTestRepeatSHA1[];

	const ch8 g_pNameSHA1[] = "SHA1";
	const ch8 *g_pTestsSHA1[] = {
		"abc",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	};
	const ch8 *g_pTestsDigestsSHA1[] = {
		"a9993e364706816aba3e25717850c26c9cd0d89d",
		"84983e441c3bd26ebaae4aa1f95129e5e54670f1",
		"34aa973cd4c4daa4f61eeb2bdbad27316534016f",
	};
	mint g_pTestRepeatSHA1[] = {1,1,15625};

	typedef TCTestHash<NMib::NCryptography::CHash_SHA1, g_pNameSHA1, g_pTestsSHA1, g_pTestsDigestsSHA1, g_pTestRepeatSHA1, fg_ArraySize(g_pTestsSHA1)> CDigestSHA1_Tests;
	DMibTestRegister(CDigestSHA1_Tests, Malterlib::Crytpography);

	extern const ch8 g_pNameSHA256[];
	extern const ch8 *g_pTestsSHA256[];
	extern const ch8 *g_pTestsDigestsSHA256[];
	extern mint g_pTestRepeatSHA256[];

	const ch8 g_pNameSHA256[] = "SHA256";
	const ch8 *g_pTestsSHA256[] = {
		"abc",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	};
	const ch8 *g_pTestsDigestsSHA256[] = {
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
	};
	mint g_pTestRepeatSHA256[] = {1,1};

	typedef TCTestHash<NMib::NCryptography::CHash_SHA256, g_pNameSHA256, g_pTestsSHA256, g_pTestsDigestsSHA256, g_pTestRepeatSHA256, fg_ArraySize(g_pTestsSHA256)> CDigestSHA256_Tests;
	DMibTestRegister(CDigestSHA256_Tests, Malterlib::Crytpography);

	extern const ch8 g_pNameSHA384[];
	extern const ch8 *g_pTestsSHA384[];
	extern const ch8 *g_pTestsDigestsSHA384[];
	extern mint g_pTestRepeatSHA384[];

	const ch8 g_pNameSHA384[] = "SHA384";
	const ch8 *g_pTestsSHA384[] = {
		"abc",
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
	};
	const ch8 *g_pTestsDigestsSHA384[] = {
		"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
		"09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
	};
	mint g_pTestRepeatSHA384[] = {1,1};

	typedef TCTestHash<NMib::NCryptography::CHash_SHA384, g_pNameSHA384, g_pTestsSHA384, g_pTestsDigestsSHA384, g_pTestRepeatSHA384, fg_ArraySize(g_pTestsSHA384)> CDigestSHA384_Tests;
	DMibTestRegister(CDigestSHA384_Tests, Malterlib::Crytpography);

	extern const ch8 g_pNameSHA512[];
	extern const ch8 *g_pTestsSHA512[];
	extern const ch8 *g_pTestsDigestsSHA512[];
	extern mint g_pTestRepeatSHA512[];

	const ch8 g_pNameSHA512[] = "SHA512";
	const ch8 *g_pTestsSHA512[] = {
		"abc",
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
	};
	const ch8 *g_pTestsDigestsSHA512[] = {
		"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		"8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
	};
	mint g_pTestRepeatSHA512[] = {1,1};

	typedef TCTestHash<NMib::NCryptography::CHash_SHA512, g_pNameSHA512, g_pTestsSHA512, g_pTestsDigestsSHA512, g_pTestRepeatSHA512, fg_ArraySize(g_pTestsSHA512)> CDigestSHA512_Tests;
	DMibTestRegister(CDigestSHA512_Tests, Malterlib::Crytpography);
}
