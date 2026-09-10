// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Cryptography/Scram>

using namespace NMib;
using namespace NMib::NContainer;
using namespace NMib::NCryptography;
using namespace NMib::NStr;

class CScram_Tests : public NMib::NTest::CTest
{
public:
	void f_DoTests()
	{
		DMibTestSuite("SCRAM SHA256")
		{
			CByteVector Salt;
			CStr SaltString = "salt";
			Salt.f_Insert((uint8 const *)SaltString.f_GetStr(), SaltString.f_GetLen());

			CStrSecure Password = "password";
			CScramSHA256Keys Keys = fg_ScramSHA256DeriveKeys(Password, Salt, 1);

			DMibExpect(Keys.m_SaltedPassword.f_GetLen(), ==, CHash_SHA256::mc_DigestSize);
			DMibExpect(Keys.m_ClientKey.f_GetLen(), ==, CHash_SHA256::mc_DigestSize);
			DMibExpect(Keys.m_ServerKey.f_GetLen(), ==, CHash_SHA256::mc_DigestSize);

			CStr AuthMessage = "n=user,r=clientnonce,r=clientnonceservernonce,s=c2FsdA==,i=1,c=biws,r=clientnonceservernonce";
			CByteVector Proof = fg_ScramSHA256ClientProof(Keys, AuthMessage);
			DMibExpect(Proof.f_GetLen(), ==, CHash_SHA256::mc_DigestSize);

			CHashDigest_SHA256 ServerSignature = fg_ScramSHA256ServerSignature(Keys, AuthMessage);
			DMibExpect(fg_ScramSHA256VerifyServerSignature(Keys, AuthMessage, ServerSignature.f_GetData(), ServerSignature.mc_Size), ==, true);

			CHashDigest_SHA256 BadServerSignature = ServerSignature;
			BadServerSignature.f_GetData()[0] ^= 0x01;
			DMibExpect(fg_ScramSHA256VerifyServerSignature(Keys, AuthMessage, BadServerSignature.f_GetData(), BadServerSignature.mc_Size), ==, false);
			DMibExpect(fg_CryptographyConstantTimeEquals(ServerSignature.f_GetData(), ServerSignature.f_GetData(), ServerSignature.mc_Size), ==, true);
			DMibExpect(fg_CryptographyConstantTimeEquals(ServerSignature.f_GetData(), BadServerSignature.f_GetData(), ServerSignature.mc_Size), ==, false);
		};
	}
};

DMibTestRegister(CScram_Tests, Malterlib::Cryptography);
