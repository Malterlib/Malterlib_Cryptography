// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Network/SSL>
#include <Mib/Test/Exception>
#include <Mib/Cryptography/Certificate>
#include <Mib/Cryptography/SymmetricCrypto>

using namespace NMib;
using namespace NMib::NStr;
using namespace NMib::NContainer;
using namespace NMib::NCryptography;

struct CMessageAuthentication_Tests : public NMib::NTest::CTest
{
	CSecureByteVector f_GetRandomBuffer(umint _Len, uint32 _Seed)
	{
		CSecureByteVector Buffer;
		Buffer.f_SetLen(_Len);
		NMisc::CRandomShiftRNG Rng{_Seed};
		for (auto &Char : Buffer)
			Char = Rng.f_GetValue<uint8>();
		return Buffer;
	}

	void f_DoTests()
	{
		DMibTestSuite("IncrementalHMAC")
		{
			CStrSecure Password("MalterlibPasswordTest");

			CSecureByteVector Salt = f_GetRandomBuffer(8, 6);

			static char const *s_pText = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";
			static char const *s_pKeyBytes = "abcdefghijklmnopqrstuvwxyz012345abcdefghijklmnopqrstuvwxyz012345";
			CByteVector PlainText;
			NMemory::fg_MemCopy(PlainText.f_GetArray(fg_StrLen(s_pText)), s_pText, fg_StrLen(s_pText));
			CSecureByteVector Key;
			NMemory::fg_MemCopy(Key.f_GetArray(fg_StrLen(s_pKeyBytes)), s_pKeyBytes, fg_StrLen(s_pKeyBytes));

			auto ContinuousHMAC = fg_MessageAuthenication_HMAC_SHA256(PlainText, Key);

			// Use multiple incremental lengths: full length and some powers of 2, and some odd ones
			static int const s_Lengths[] = {89, 1, 8, 64, 3, 9};

			for (auto Length : s_Lengths)
			{
				DMibTestPath(fg_Format("Buffer length: {}", Length));

				CIncrementalHMAC IncrementalHMAC(EDigestType_SHA256, Key);

				for (int Offset = 0; Offset < s_Lengths[0]; Offset += Length)
				{
					int ThisTime = fg_Min(s_Lengths[0] - Offset, Length);
					IncrementalHMAC.f_Update(PlainText.f_GetArray() + Offset, ThisTime);
				}
				NCryptography::CHashDigest_SHA256 Result;
				auto nBytes = IncrementalHMAC.f_Finalize(Result.f_GetData(), Result.mc_Size);
				DMibExpect(Result, ==, ContinuousHMAC);
				DMibExpect(nBytes, ==, ContinuousHMAC.mc_Size);
			}

			{
				DMibTestPath("IncorrectKey");
				Key[0] = 'A';
				CIncrementalHMAC IncrementalHMAC(EDigestType_SHA256, Key);
				IncrementalHMAC.f_Update(PlainText.f_GetArray(), s_Lengths[0]);
				NCryptography::CHashDigest_SHA256 Result;
				auto nBytes = IncrementalHMAC.f_Finalize(Result.f_GetData(), Result.mc_Size);
				DMibExpect(Result, !=, ContinuousHMAC);
				DMibExpect(nBytes, ==, ContinuousHMAC.mc_Size);
			}
		};
	}
};

DMibTestRegister(CMessageAuthentication_Tests, Malterlib::Cryptography);
