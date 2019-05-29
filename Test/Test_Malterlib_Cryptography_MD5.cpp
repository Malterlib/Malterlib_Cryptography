// Copyright © 2015 Hansoft AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Cryptography/Hashes/SHA>
#include <Mib/Cryptography/Hashes/MD5>

#if 0

#include <SDK/MD5/md5.h>
// CMalterlibTest no longer available

template <typename t_CHash, const ch8 _pName[], const ch8 *_pTests[], const ch8 *_pTestDigests[], mint _pTestRepeat[], mint _nTests, bool _bIsMD5>
class TCTestHash : public CMalterlibTest
{
public:

	#define RANDMAX 2147483646 // RANDMAX = M - 1

	/*
	Park and Miller's psuedo-random number generator.
	*/
	static aint next;
	aint Rand ()
	{
		static const aint A = 16807;
		static const aint M = 2147483647;   // 2^31 - 1
		static const aint q = M / A;       // M / A
		static const aint r = M % A;         // M % A

		next = A * (next % q) - r * (next / q);
		if (next < 0) next += M;
		return next;
	}

	bool f_AutomaticTest()
	{
		return true;
	}

	NMib::NStr::CStr Certify(CTestInterface &_Interface)
	{
		typedef t_CHash CHash;
		typedef typename t_CHash::CMessageDigest CHashDigest;
		CHash Hash;
		CHashDigest Digest;

		if (0)
		{
			NMib::NFile::CFile File;

			NMib::NStr::CStr FileName = "X:\\Temp\\3-Iron.2004.DVDRip.XviD-GaMo.avi";

			if (NMib::NFile::CFile::fs_FileExists(FileName, NMib::NFile::EFileAttrib_File))
			{
				try
				{
					File.f_Open(FileName, NMib::NFile::EFileOpen_Read);
				}
				catch (NMib::NFile::CExceptionFile)
				{
					return "Failed to open test file";
				}

				int Len = File.f_GetLength();
				int SaveLen = Len;

				NMib::NContainer::CByteVector Data;

				Data.f_SetLen(65536);
				uint8 *pData = Data.f_GetArray();

				NMib::NTime::CTimer Timer;
				{
					DMibScopeTimer(Timer);

					while (Len)
					{
						int ThisTime = NMib::fg_Min(Len, 65536);
						File.f_Read(pData, ThisTime);
						Hash.f_AddData(pData, ThisTime);
						Len -= ThisTime;
					}
					Digest = Hash;
				}
				fp64 Time = Timer.f_GetTime();

				{
					NMib::NFile::TCBinaryStreamFile<> OutFile;
					OutFile.f_Open((NMib::NStr::CStr::CFormat("Test.ids.{}") << _pName).f_GetStr(), NMib::NFile::EFileOpen_Write);
					NMib::NStr::CStr Data = Digest.f_GetString();
					OutFile.f_FeedBytes(Data.f_GetStr(), 32);
					DMibTrace("{}\n", Data);
					DMibTrace("Generation took {} seconds ({} MiB/second).\n", Time << (fp64(SaveLen) / fp64(1024.0*1024.0)) / Timer.f_GetTime());

				}
			}
		}

		for (mint i = 0; i < _nTests; ++i)
		{
			Hash.f_Reset();
			mint Len = NMib::NStr::fg_StrLen(_pTests[i]);
			for (mint j = 0; j < _pTestRepeat[i]; ++j)
				Hash.f_AddData(_pTests[i], Len);

			Digest = CHashDigest(Hash);
			NMib::NStr::CStr DigestString = Digest.f_GetString();
			DMibTrace("Malterlib{}: {} should be {}\n", _pName << DigestString << _pTestDigests[i]);
			if (NMib::NStr::fg_StrCmpNoCase(DigestString, _pTestDigests[i]) != 0)
			{
				return "Digest test failed";
			}
		}

		{
			int TestSize = 512*1024*1024; // 512 MB creation test

			next = 1321564;
			uint8 *pData = DMibNew uint8[TestSize];

			for (int i = 0; i < TestSize / 4; ++i)
			{
				((uint32 *)pData)[i] = Rand();
			}

			int nTests = 1;

			NMib::NTime::CTimerMin TimerAlloc;
			CHashDigest Digest2;

			{
				DMibScopeTimerMin(TimerAlloc);
				Hash.f_Reset();
				for (int i = 0; i < nTests; ++i)
					Hash.f_AddData(pData, TestSize);
				Digest2 = Hash;
			}
			DMibTrace("Malterlib{}: {}\n", _pName << Digest2.f_GetString());

			fp64 MiBSec = (fp64(TestSize*nTests) / TimerAlloc.f_GetTime()) / (1024.0 * 1024.0);

			DMibTrace("Malterlib{} of {} MiB of data in {} seconds: Performance {} MiB/second\n", _pName << (TestSize*nTests)/(1024*1024) << TimerAlloc.f_GetTime() << MiBSec);

			delete pData;
		}

		{
			int TestSize = 4*1024; // L1 cache test

			next = 1321564;
			uint8 *pData = DMibNew uint8[TestSize];

			for (int i = 0; i < TestSize / 4; ++i)
			{
				((uint32 *)pData)[i] = Rand();
			}

			// Add to cache
			Hash.f_Reset();
			Hash.f_AddData(pData, TestSize);
			int nTests = 128 * 1024;

			NMib::NTime::CTimerMin TimerAlloc;
			CHashDigest Digest2;

			{
				DMibScopeTimerMin(TimerAlloc);
				Hash.f_Reset();
				for (int i = 0; i < nTests; ++i)
					Hash.f_AddData(pData, TestSize);
				Digest2 = Hash;
			}
			DMibTrace("Malterlib{}: {}\n", _pName << Digest2.f_GetString());

			fp64 MiBSec = (fp64(TestSize*nTests) / TimerAlloc.f_GetTime()) / (1024.0 * 1024.0);

			DMibTrace("Malterlib{} of {} MiB of cached data in {} seconds: Performance {} MiB/second\n", _pName << (TestSize*nTests)/(1024*1024) << TimerAlloc.f_GetTime() << MiBSec);

			delete pData;
		}

		if (_bIsMD5)
		{
			int TestSize = 512*1024*1024; // 512 MB MalterlibMD5 creation test

			MD5 ccMD5;

			next = 1321564;
			uint8 *pData = DMibNew uint8[TestSize];

			for (int i = 0; i < TestSize / 4; ++i)
			{
				((uint32 *)pData)[i] = Rand();
			}

			int nTests = 1;

			NMib::NTime::CTimerMin TimerAlloc;
			NMib::NCryptography::CHashDigest_MD5 Digest2;

			{
				DMibScopeTimerMin(TimerAlloc);
				for (int i = 0; i < nTests; ++i)
					ccMD5.update(pData, TestSize);
				ccMD5.finalize();
			}
			fp64 MiBSec = (fp64(TestSize*nTests) / TimerAlloc.f_GetTime()) / (1024.0 * 1024.0);

			DMibTrace("ccMD5 of {} MiB of data in {} seconds: Performance {} MiB/second\n", (TestSize*nTests)/(1024*1024) << TimerAlloc.f_GetTime() << MiBSec);

			delete pData;
		}

		if (_bIsMD5)
		{
			int TestSize = 4*1024; // L1 cache test
			MD5 ccMD5;

			next = 1321564;
			uint8 *pData = DMibNew uint8[TestSize];

			for (int i = 0; i < TestSize / 4; ++i)
			{
				((uint32 *)pData)[i] = Rand();
			}

			// Add to cache
			int nTests = 128 * 1024;

			NMib::NTime::CTimerMin TimerAlloc;
			NMib::NCryptography::CHashDigest_MD5 Digest2;

			{
				DMibScopeTimerMin(TimerAlloc);
				for (int i = 0; i < nTests; ++i)
					ccMD5.update(pData, TestSize);
				ccMD5.finalize();
			}
			fp64 MiBSec = (fp64(TestSize*nTests) / TimerAlloc.f_GetTime()) / (1024.0 * 1024.0);

			DMibTrace("ccMD5 of {} MiB of cached data in {} seconds: Performance {} MiB/second\n", (TestSize*nTests)/(1024*1024) << TimerAlloc.f_GetTime() << MiBSec);

			delete pData;
		}

		return ("");
	}


};

template <typename t_CHash, const ch8 _pName[], const ch8 *_pTests[], const ch8 *_pTestDigests[], mint _pTestRepeat[], mint _nTests, bool _bIsMD5>
aint TCTestHash<t_CHash, _pName, _pTests, _pTestDigests, _pTestRepeat, _nTests, _bIsMD5>::next = 1;

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

typedef TCTestHash<NMib::NCryptography::CHash_MD5, g_pNameMD5, g_pTestsMD5, g_pTestsDigestsMD5, g_pTestRepeatMD5, sizeof(g_pTestsMD5) / sizeof(g_pTestsMD5[0]), true> CTestMD5;
DMibRuntimeClass(CMalterlibTest, CTestMD5);

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
	"A9993E364706816ABA3E25717850C26C9CD0D89D",
	"84983E441C3BD26EBAAE4AA1F95129E5E54670F1",
	"34AA973CD4C4DAA4F61EEB2BDBAD27316534016F",
};
mint g_pTestRepeatSHA1[] = {1,1,15625};

typedef TCTestHash<NMib::NCryptography::CHash_SHA1, g_pNameSHA1, g_pTestsSHA1, g_pTestsDigestsSHA1, g_pTestRepeatSHA1, sizeof(g_pTestsSHA1) / sizeof(g_pTestsSHA1[0]), false> CTestSHA1;
DMibRuntimeClass(CMalterlibTest, CTestSHA1);

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

typedef TCTestHash<NMib::NCryptography::CHash_SHA256, g_pNameSHA256, g_pTestsSHA256, g_pTestsDigestsSHA256, g_pTestRepeatSHA256, sizeof(g_pTestsSHA256) / sizeof(g_pTestsSHA256[0]), false> CTestSHA256;
DMibRuntimeClass(CMalterlibTest, CTestSHA256);

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

typedef TCTestHash<NMib::NCryptography::CHash_SHA384, g_pNameSHA384, g_pTestsSHA384, g_pTestsDigestsSHA384, g_pTestRepeatSHA384, sizeof(g_pTestsSHA384) / sizeof(g_pTestsSHA384[0]), false> CTestSHA384;
DMibRuntimeClass(CMalterlibTest, CTestSHA384);

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

typedef TCTestHash<NMib::NCryptography::CHash_SHA512, g_pNameSHA512, g_pTestsSHA512, g_pTestsDigestsSHA512, g_pTestRepeatSHA512, sizeof(g_pTestsSHA512) / sizeof(g_pTestsSHA512[0]), false> CTestSHA512;
DMibRuntimeClass(CMalterlibTest, CTestSHA512);

#endif
