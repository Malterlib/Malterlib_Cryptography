// Copyright © 2015 Hansoft AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Cryptography/UUID>
#include <Mib/Test/Exception>
#include <Mib/Process/Platform>

namespace
{
	using namespace NMib::NTest;

	class CMisc_Tests : public CTest
	{
	public:

		CMisc_Tests()
		{
		}

		void f_DoTests()
		{
			DMibTestSuite("Computer name")
			{
				DMibExpect(NMib::NProcess::NPlatform::fg_Process_GetUserName(), !=, "");
				DMibTest(DMibExpr(NMib::NProcess::NPlatform::fg_Process_GetComputerDomain()) != DMibExpr("") || DMibExpr(NMib::NProcess::NPlatform::fg_Process_GetComputerDomain()) == DMibExpr(""));
				DMibExpect(NMib::NProcess::NPlatform::fg_Process_GetComputerName(), !=, "");
				DMibExpect(NMib::NProcess::NPlatform::fg_Process_GetComputerAddress(), !=, "");
			};

			DMibTestSuite("UUID")
			{
				using namespace NMib::NCryptography;
				NMib::NCryptography::CUniversallyUniqueIdentifier SecureRandom0(EUniversallyUniqueIdentifierGenerate_Secure);
				NMib::NCryptography::CUniversallyUniqueIdentifier SecureRandom1(EUniversallyUniqueIdentifierGenerate_Secure);
				NMib::NCryptography::CUniversallyUniqueIdentifier Random0(EUniversallyUniqueIdentifierGenerate_Random);
				NMib::NCryptography::CUniversallyUniqueIdentifier Random1(EUniversallyUniqueIdentifierGenerate_Random);
				NMib::NCryptography::CUniversallyUniqueIdentifier RootNamespace("{C2EA34BB-5C04-4945-A798-D5685B7CD2A8}");
				NMib::NCryptography::CUniversallyUniqueIdentifier StringHash0(EUniversallyUniqueIdentifierGenerate_StringHash, RootNamespace, "Test0");
				NMib::NCryptography::CUniversallyUniqueIdentifier StringHash1(EUniversallyUniqueIdentifierGenerate_StringHash, RootNamespace, "Test1");
				constexpr NMib::NCryptography::CUniversallyUniqueIdentifier RootNamespaceConst(0xC2EA34BBu, 0x5C04, 0x4945, 0xA798, constant_uint64(0xD5685B7CD2A8));

				DMibExpect(RootNamespaceConst, ==, RootNamespace);

				DMibExpect(RootNamespace.f_GetAsString(EUniversallyUniqueIdentifierFormat_Registry), ==, "{C2EA34BB-5C04-4945-A798-D5685B7CD2A8}");
				DMibExpect(RootNamespace.f_GetAsString(EUniversallyUniqueIdentifierFormat_Bare), ==, "C2EA34BB-5C04-4945-A798-D5685B7CD2A8");
				DMibExpect(RootNamespace.f_GetAsString(EUniversallyUniqueIdentifierFormat_AlphaNum), ==, "C2EA34BB5C044945A798D5685B7CD2A8");

				NMib::NCryptography::CUniversallyUniqueIdentifier ParseBare("C2EA34BB-5C04-4945-A798-D5685B7CD2A8", EUniversallyUniqueIdentifierFormat_Bare);
				DMibExpect(ParseBare.f_GetAsString(EUniversallyUniqueIdentifierFormat_Bare), ==, "C2EA34BB-5C04-4945-A798-D5685B7CD2A8");
				DMibExpectException
					(
						NMib::NCryptography::CUniversallyUniqueIdentifier("C2EA34BB5C044945A798D5685B7CD2A8", EUniversallyUniqueIdentifierFormat_AlphaNum)
						, DMibErrorInstance("EUniversallyUniqueIdentifierFormat_AlphaNum parsing of GUID not supported")
					)
				;

				DMibExpect(SecureRandom0, !=, SecureRandom1);
				DMibExpect(Random0, !=, Random1);
				DMibExpect(StringHash0, !=, StringHash1);
			};
		}
	};

	DMibTestRegister(CMisc_Tests, Malterlib::Cryptography);

}

