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

class CMessageAuthentication_Tests : public NMib::NTest::CTest
{
public:
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

			static const char *Text = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";
			static const char *KeyBytes = "abcdefghijklmnopqrstuvwxyz012345abcdefghijklmnopqrstuvwxyz012345";
			CByteVector PlainText;
			NMemory::fg_MemCopy(PlainText.f_GetArray(fg_StrLen(Text)), Text, fg_StrLen(Text));
			CSecureByteVector Key;
			NMemory::fg_MemCopy(Key.f_GetArray(fg_StrLen(KeyBytes)), KeyBytes, fg_StrLen(KeyBytes));

			auto ContinuousHMAC =  fg_MessageAuthenication_HMAC_SHA256(PlainText, Key);

			// Use multiple incremental lengths: full length and some powers of 2, and some odd ones
			static const int Lengths[] = { 89, 1, 8, 64, 3, 9 };

			for (auto Length : Lengths)
			{
				DMibTestPath(fg_Format("Buffer length: {}", Length));

				CIncrementalHMAC IncrementalHMAC(EDigestType_SHA256, Key);

				for (int i = 0; i < Lengths[0]; i += Lengths[i])
				{
					int ThisTime = fg_Min(Lengths[0] - i, Lengths[i]);
					IncrementalHMAC.f_Update(PlainText.f_GetArray() + i, ThisTime);
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
				IncrementalHMAC.f_Update(PlainText.f_GetArray(), Lengths[0]);
				NCryptography::CHashDigest_SHA256 Result;
				auto nBytes = IncrementalHMAC.f_Finalize(Result.f_GetData(), Result.mc_Size);
				DMibExpect(Result, !=, ContinuousHMAC);
				DMibExpect(nBytes, ==, ContinuousHMAC.mc_Size);
			}
		};
	}
};

DMibTestRegister(CMessageAuthentication_Tests, Malterlib::Crytpography);
