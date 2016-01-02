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
				DMibTest(DMibExpr(NMib::NProcess::NPlatform::fg_Process_GetUserName()) != DMibExpr(""));
				DMibTest(DMibExpr(NMib::NProcess::NPlatform::fg_Process_GetComputerDomain()) != DMibExpr("") || DMibExpr(NMib::NProcess::NPlatform::fg_Process_GetComputerDomain()) == DMibExpr(""));
				DMibTest(DMibExpr(NMib::NProcess::NPlatform::fg_Process_GetComputerName()) != DMibExpr(""));
				DMibTest(DMibExpr(NMib::NProcess::NPlatform::fg_Process_GetComputerAddress()) != DMibExpr(""));
			};

			DMibTestSuite("UUID")
			{
				using namespace NMib::NDataProcessing;
				NMib::NDataProcessing::CUniversallyUniqueIdentifier SecureRandom0(EUniversallyUniqueIdentifierGenerate_Secure);
				NMib::NDataProcessing::CUniversallyUniqueIdentifier SecureRandom1(EUniversallyUniqueIdentifierGenerate_Secure);
				NMib::NDataProcessing::CUniversallyUniqueIdentifier Random0(EUniversallyUniqueIdentifierGenerate_Random);
				NMib::NDataProcessing::CUniversallyUniqueIdentifier Random1(EUniversallyUniqueIdentifierGenerate_Random);
				NMib::NDataProcessing::CUniversallyUniqueIdentifier RootNamespace("{C2EA34BB-5C04-4945-A798-D5685B7CD2A8}");
				NMib::NDataProcessing::CUniversallyUniqueIdentifier StringHash0(EUniversallyUniqueIdentifierGenerate_StringHash, RootNamespace, "Test0");
				NMib::NDataProcessing::CUniversallyUniqueIdentifier StringHash1(EUniversallyUniqueIdentifierGenerate_StringHash, RootNamespace, "Test1");

				DMibTest(DMibExpr(RootNamespace.f_GetAsString(EUniversallyUniqueIdentifierFormat_Registry)) == DMibExpr("{C2EA34BB-5C04-4945-A798-D5685B7CD2A8}"));
				DMibTest(DMibExpr(RootNamespace.f_GetAsString(EUniversallyUniqueIdentifierFormat_Bare)) == DMibExpr("C2EA34BB-5C04-4945-A798-D5685B7CD2A8"));
				DMibTest(DMibExpr(RootNamespace.f_GetAsString(EUniversallyUniqueIdentifierFormat_AlphaNum)) == DMibExpr("C2EA34BB5C044945A798D5685B7CD2A8"));

				NMib::NDataProcessing::CUniversallyUniqueIdentifier ParseBare("C2EA34BB-5C04-4945-A798-D5685B7CD2A8", EUniversallyUniqueIdentifierFormat_Bare);
				DMibTest(DMibExpr(ParseBare.f_GetAsString(EUniversallyUniqueIdentifierFormat_Bare)) == DMibExpr("C2EA34BB-5C04-4945-A798-D5685B7CD2A8"));
				DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(NMib::NDataProcessing::CUniversallyUniqueIdentifier("C2EA34BB5C044945A798D5685B7CD2A8", EUniversallyUniqueIdentifierFormat_AlphaNum)));
				
				DMibTest(DMibExpr(SecureRandom0) != DMibExpr(SecureRandom1));
				DMibTest(DMibExpr(Random0) != DMibExpr(Random1));
				DMibTest(DMibExpr(StringHash0) != DMibExpr(StringHash1));
			};
			
			
		}		
	};

	DMibTestRegister(CMisc_Tests, Malterlib::Cryptography);

}

