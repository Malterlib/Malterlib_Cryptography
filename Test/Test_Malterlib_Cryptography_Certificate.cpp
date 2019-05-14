// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Network/SSL>
#include <Mib/Test/Exception>
#include <Mib/Cryptography/Certificate>
#include <Mib/Cryptography/SymmetricCrypto>

using namespace NMib;
using namespace NMib::NStr;
using namespace NMib::NContainer;
using namespace NMib::NCryptography;

class CCertificate_Tests : public NMib::NTest::CTest
{
public:
	void f_DoTests()
	{
		DMibTestSuite("Properties")
		{
			CCertificate::fs_RegisterExtension
				(
					"1.3.6.1.4.1.47722.1.2"
					, "MalterlibTest"
					, "Malterlib Test"
				)
			;

			CPublicKeySetting TestKeySetting = CPublicKeySettings_EC_secp256r1{};
			CByteVector ServerPublicCertificateData;
			CSecureByteVector ServerPrivateKeyData;
			CCertificateOptions ServerOptions;
			ServerOptions.m_CommonName = "localhost0";
			ServerOptions.m_Hostnames = fg_CreateVector<CStr>("localhost1", "localhost2");
			ServerOptions.m_KeySetting = TestKeySetting;
			auto &ServerExtension = ServerOptions.m_Extensions["MalterlibTest"].f_Insert();
			ServerExtension.m_Value = "Test0";
			ServerExtension.m_bCritical = false;
			auto &ServerExtensionCritical = ServerOptions.m_Extensions["MalterlibTest"].f_Insert();
			ServerExtensionCritical.m_Value = "Test1";
			ServerExtensionCritical.m_bCritical = true;
			
			CCertificate::fs_GenerateSelfSignedCertAndKey(ServerOptions, ServerPublicCertificateData, ServerPrivateKeyData);

			auto ServerHostNames = CCertificate::fs_GetCertificateHostnames(ServerPublicCertificateData, false);
			auto ServerExtensions = CCertificate::fs_GetCertificateExtensions(ServerPublicCertificateData);
			auto Info = CCertificate::fs_GetCertificateDescription(ServerPublicCertificateData);
			
			DMibExpect(ServerHostNames, ==, fg_CreateVector<CStr>("localhost1", "localhost2"));
			DMibExpect(ServerExtensions["MalterlibTest"], ==, ServerOptions.m_Extensions["MalterlibTest"]);

			{
				CByteVector ClientPublicCertificateData;
				CSecureByteVector ClientPrivateKeyData;

				CCertificateOptions ClientOptions;
				ClientOptions.m_CommonName = "localhost3";
				ClientOptions.m_KeySetting = TestKeySetting;
				ClientOptions.m_Hostnames = fg_CreateVector<CStr>("localhost4", "localhost5");
				auto &ClientExtension = ClientOptions.m_Extensions["MalterlibTest"].f_Insert();
				ClientExtension.m_Value = "Test2";
				ClientExtension.m_bCritical = false;
				auto &ClientExtensionCritical = ClientOptions.m_Extensions["MalterlibTest"].f_Insert();
				ClientExtensionCritical.m_Value = "Test3";
				ClientExtensionCritical.m_bCritical = true;
				
				CByteVector CertificateRequestData;
				CCertificate::fs_GenerateClientCertificateRequest(ClientOptions, CertificateRequestData, ClientPrivateKeyData);
				CCertificate::fs_SignClientCertificate(ServerPublicCertificateData, ServerPrivateKeyData, CertificateRequestData, ClientPublicCertificateData);
				
				auto ClientHostNames = CCertificate::fs_GetCertificateHostnames(ClientPublicCertificateData, false);
				auto ClientExtensions = CCertificate::fs_GetCertificateExtensions(ClientPublicCertificateData);
				
				DMibExpect(ClientHostNames, ==, fg_CreateVector<CStr>("localhost4", "localhost5"));
				DMibExpect(ClientExtensions["MalterlibTest"], ==, ClientOptions.m_Extensions["MalterlibTest"]);
			}
			{
				DMibTestPath("Extensions only");
				CByteVector ClientPublicCertificateData;
				CSecureByteVector ClientPrivateKeyData;
				
				CCertificateOptions ClientOptions;
				ClientOptions.m_CommonName = "localhost3";
				ClientOptions.m_KeySetting = TestKeySetting;
				auto &ClientExtension = ClientOptions.m_Extensions["MalterlibTest"].f_Insert();
				ClientExtension.m_Value = "Test2";
				ClientExtension.m_bCritical = false;
				auto &ClientExtensionCritical = ClientOptions.m_Extensions["MalterlibTest"].f_Insert();
				ClientExtensionCritical.m_Value = "Test3";
				ClientExtensionCritical.m_bCritical = true;
				
				CByteVector CertificateRequestData;
				CCertificate::fs_GenerateClientCertificateRequest(ClientOptions, CertificateRequestData, ClientPrivateKeyData);
				CCertificate::fs_SignClientCertificate(ServerPublicCertificateData, ServerPrivateKeyData, CertificateRequestData, ClientPublicCertificateData);
				
				auto ClientExtensions = CCertificate::fs_GetCertificateExtensions(ClientPublicCertificateData);
				
				DMibExpect(ClientExtensions["MalterlibTest"], ==, ClientOptions.m_Extensions["MalterlibTest"]);
			}
		};
	}
};

DMibTestRegister(CCertificate_Tests, Malterlib::Crytpography);
