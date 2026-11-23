// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Network/SSL>
#include <Mib/Test/Exception>
#include <Mib/Cryptography/Certificate>
#include <Mib/Cryptography/SymmetricCrypto>
#include <Mib/Cryptography/PublicCrypto>
#include <Mib/Cryptography/BoringSSL>
#include <Mib/Encoding/Base64>

using namespace NMib;
using namespace NMib::NStr;
using namespace NMib::NContainer;
using namespace NMib::NCryptography;

struct CCertificate_Tests : public NMib::NTest::CTest
{
	void f_DoTests();
};

void CCertificate_Tests::f_DoTests()
{
	DMibTestSuite("MalformedVersion")
	{
		// BoringSSL is built to read a certificate whose version field is 3, which is no version, as version 3, whose field is 2,
		// as certificates in use have it (OPENSSL_ALLOW_MALFORMED_X509_VERSION)
		CByteVector CertificateData;
		CSecureByteVector PrivateKeyData;
		CCertificateOptions Options;
		Options.m_CommonName = "malformed";
		Options.m_Hostnames = fg_CreateVector<CStr>("malformed1");
		Options.m_KeySetting = CPublicKeySettings_EC_Secp256r1{};
		CCertificate::fs_GenerateSelfSignedCertAndKey(Options, CertificateData, PrivateKeyData);

		X509 *pCertificate = NBoringSSL::fg_LoadCertificate(CertificateData);
		auto Cleanup = g_OnScopeExit / [&]
			{
				X509_free(pCertificate);
			}
		;
		uint8_t *pDer = nullptr;
		int DerLength = i2d_X509(pCertificate, &pDer);
		DMibAssert(DerLength, >, 0);
		CByteVector Der;
		Der.f_Insert(pDer, DerLength);
		OPENSSL_free(pDer);

		// The explicitly tagged version of the TBSCertificate: [0] { INTEGER 2 }
		uint8_t const VersionField[] = {0xA0, 0x03, 0x02, 0x01, 0x02};
		umint iVersion = 0;
		for (; iVersion + sizeof(VersionField) <= Der.f_GetLen(); ++iVersion)
		{
			if (NMemory::fg_MemCmp(Der.f_GetArray() + iVersion, VersionField, sizeof(VersionField)) == 0)
				break;
		}
		DMibAssert(iVersion + sizeof(VersionField), <=, Der.f_GetLen());
		Der[iVersion + sizeof(VersionField) - 1] = 0x03;

		CStr Base64 = NEncoding::fg_Base64Encode(Der);
		CStr Pem = "-----BEGIN CERTIFICATE-----\n";
		for (umint iLine = 0; iLine < Base64.f_GetLen(); iLine += 64)
			Pem += "{}\n"_f << Base64.f_Extract(iLine, 64);
		Pem += "-----END CERTIFICATE-----\n";
		CByteVector MalformedData;
		MalformedData.f_Insert((uint8 const *)Pem.f_GetStr(), Pem.f_GetLen());

		DMibExpect(CCertificate::fs_GetCertificateHostnames(MalformedData, false), ==, fg_CreateVector<CStr>("malformed1"));
	};

	DMibTestSuite("Properties")
	{
		CCertificate::fs_RegisterExtension("1.3.6.1.4.1.47722.1.2", "MalterlibTest", "Malterlib Test");

		CPublicKeySetting TestKeySetting = CPublicKeySettings_EC_Secp256r1{};
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
		auto Fingerprint = CCertificate::fs_GetCertificateFingerprint(ServerPublicCertificateData);
		auto FingerprintData = CCertificate::fs_GetCertificateFingerprintData(ServerPublicCertificateData);
		auto TLSServerEndPointData = CCertificate::fs_GetCertificateTLSServerEndPointData(ServerPublicCertificateData);

		DMibExpect(ServerHostNames, ==, fg_CreateVector<CStr>("localhost1", "localhost2"));
		DMibExpect(ServerExtensions["MalterlibTest"], ==, ServerOptions.m_Extensions["MalterlibTest"]);
		DMibExpect(Fingerprint.f_GetLen(), ==, FingerprintData.f_GetLen() * 2);
		DMibExpect(FingerprintData.f_GetLen(), ==, umint(32));
		DMibExpect(TLSServerEndPointData, ==, FingerprintData);

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

	DMibTestSuite("Chain Verification")
	{
		CPublicKeySetting TestKeySetting = CPublicKeySettings_EC_Secp256r1{};

		// An explicitly pinned anchor needs no CA:TRUE extension for path building, when the verification allows it.
		CCertificateVerifyOptions PinnedAnchor;
		PinnedAnchor.m_bAllowPinnedTrustAnchor = true;

		CByteVector AuthorityCertificateData;
		CSecureByteVector AuthorityPrivateKeyData;
		CCertificateOptions AuthorityOptions;
		AuthorityOptions.m_CommonName = "Test CA";
		AuthorityOptions.m_KeySetting = TestKeySetting;
		CCertificate::fs_GenerateSelfSignedCertAndKey(AuthorityOptions, AuthorityCertificateData, AuthorityPrivateKeyData);

		CByteVector ClientCertificateData;
		CSecureByteVector ClientPrivateKeyData;
		{
			CCertificateOptions ClientOptions;
			ClientOptions.m_CommonName = "Test Client";
			ClientOptions.m_KeySetting = TestKeySetting;

			CByteVector CertificateRequestData;
			CCertificate::fs_GenerateClientCertificateRequest(ClientOptions, CertificateRequestData, ClientPrivateKeyData);
			CCertificate::fs_SignClientCertificate(AuthorityCertificateData, AuthorityPrivateKeyData, CertificateRequestData, ClientCertificateData);
		}

		{
			DMibTestPath("Valid Chain");

			NStr::CStr Error;
			TCVector<CByteVector> VerifiedChain;
			bool bValid = CCertificate::fs_VerifyCertificateChain
				(
					fg_CreateVector(ClientCertificateData)
					, AuthorityCertificateData
					, false
					, EVerificationPurpose_Any
					, PinnedAnchor
					, &VerifiedChain
					, Error
				)
			;

			DMibExpectTrue(bValid);
			DMibExpect(Error, ==, CStr());

			DMibExpect(VerifiedChain.f_GetLen(), ==, umint(2));
			DMibExpect(CCertificate::fs_GetCertificateFingerprint(VerifiedChain[0]), ==, CCertificate::fs_GetCertificateFingerprint(ClientCertificateData));
			DMibExpect(CCertificate::fs_GetCertificateFingerprint(VerifiedChain[1]), ==, CCertificate::fs_GetCertificateFingerprint(AuthorityCertificateData));
		}

		{
			DMibTestPath("Pinned Anchor Needs Option");

			NStr::CStr Error;
			bool bValid = CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientCertificateData), AuthorityCertificateData, false, EVerificationPurpose_Any, {}, nullptr, Error);

			DMibExpectFalse(bValid);
			DMibExpect(Error, ==, CStr("invalid CA certificate"));
		}

		{
			DMibTestPath("Pinned Anchor Only At The Top");

			// Under a pinned anchor, an intermediate that isn't a CA issues no certificates, while one that is a CA does
			for (bool bIntermediateIsCA : {false, true})
			{
				DMibTestPath(bIntermediateIsCA ? "CA Intermediate" : "Intermediate Not A CA");

				CByteVector IntermediateCertificateData;
				CSecureByteVector IntermediatePrivateKeyData;
				{
					CCertificateOptions IntermediateOptions;
					IntermediateOptions.m_CommonName = "Intermediate Under Pinned Anchor";
					IntermediateOptions.m_KeySetting = TestKeySetting;
					if (bIntermediateIsCA)
					{
						IntermediateOptions.f_AddExtension_BasicConstraints(true);
						IntermediateOptions.f_AddExtension_KeyUsage(EKeyUsage_CertificateSign);
					}

					CByteVector CertificateRequestData;
					CCertificate::fs_GenerateClientCertificateRequest(IntermediateOptions, CertificateRequestData, IntermediatePrivateKeyData);
					CCertificate::fs_SignClientCertificate(AuthorityCertificateData, AuthorityPrivateKeyData, CertificateRequestData, IntermediateCertificateData);
				}

				CByteVector LeafCertificateData;
				{
					CCertificateOptions LeafOptions;
					LeafOptions.m_CommonName = "Leaf Under Intermediate";
					LeafOptions.m_KeySetting = TestKeySetting;

					CByteVector CertificateRequestData;
					CSecureByteVector LeafPrivateKeyData;
					CCertificate::fs_GenerateClientCertificateRequest(LeafOptions, CertificateRequestData, LeafPrivateKeyData);
					CCertificate::fs_SignClientCertificate(IntermediateCertificateData, IntermediatePrivateKeyData, CertificateRequestData, LeafCertificateData);
				}

				NStr::CStr Error;
				bool bValid = CCertificate::fs_VerifyCertificateChain
					(
						fg_CreateVector(LeafCertificateData, IntermediateCertificateData)
						, AuthorityCertificateData
						, false
						, EVerificationPurpose_Any
						, PinnedAnchor
						, nullptr
						, Error
					)
				;

				DMibExpect(bValid, ==, bIntermediateIsCA);
				DMibExpect(Error, ==, CStr(bIntermediateIsCA ? "" : "invalid CA certificate"));
			}
		}

		{
			DMibTestPath("Pinned Anchor Extended Key Usage");

			CByteVector ServerOnlyCertificateData;
			CSecureByteVector ServerOnlyPrivateKeyData;
			CCertificateOptions ServerOnlyOptions;
			ServerOnlyOptions.m_CommonName = "Server Only Anchor";
			ServerOnlyOptions.m_KeySetting = TestKeySetting;
			ServerOnlyOptions.m_Extensions["2.5.29.37"].f_Insert().m_Value = "serverAuth";
			CCertificate::fs_GenerateSelfSignedCertAndKey(ServerOnlyOptions, ServerOnlyCertificateData, ServerOnlyPrivateKeyData);

			CByteVector LeafCertificateData;
			{
				CCertificateOptions LeafOptions;
				LeafOptions.m_CommonName = "Leaf Under Server Only Anchor";
				LeafOptions.m_KeySetting = TestKeySetting;

				CByteVector CertificateRequestData;
				CSecureByteVector LeafPrivateKeyData;
				CCertificate::fs_GenerateClientCertificateRequest(LeafOptions, CertificateRequestData, LeafPrivateKeyData);
				CCertificate::fs_SignClientCertificate(ServerOnlyCertificateData, ServerOnlyPrivateKeyData, CertificateRequestData, LeafCertificateData);
			}

			NStr::CStr Error;
			bool bValid = CCertificate::fs_VerifyCertificateChain
				(
					fg_CreateVector(LeafCertificateData)
					, ServerOnlyCertificateData
					, false
					, EVerificationPurpose_ClientAuth
					, PinnedAnchor
					, nullptr
					, Error
				)
			;

			DMibExpectFalse(bValid);
			DMibExpect(Error, ==, CStr("unsupported certificate purpose"));
		}

		{
			DMibTestPath("Wrong CA");

			CByteVector OtherCACertificateData;
			CSecureByteVector OtherCAPrivateKeyData;
			CCertificateOptions OtherCAOptions;
			OtherCAOptions.m_CommonName = "Other Test CA";
			OtherCAOptions.m_KeySetting = TestKeySetting;
			CCertificate::fs_GenerateSelfSignedCertAndKey(OtherCAOptions, OtherCACertificateData, OtherCAPrivateKeyData);

			NStr::CStr Error;
			bool bValid = CCertificate::fs_VerifyCertificateChain
				(
					fg_CreateVector(ClientCertificateData)
					, OtherCACertificateData
					, false
					, EVerificationPurpose_Any
					, PinnedAnchor
					, nullptr
					, Error
				)
			;

			DMibExpectFalse(bValid);
			DMibExpectFalse(Error.f_IsEmpty());
		}

		{
			DMibTestPath("Empty Chain");

			NStr::CStr Error;
			bool bValid = CCertificate::fs_VerifyCertificateChain({}, AuthorityCertificateData, false, EVerificationPurpose_Any, PinnedAnchor, nullptr, Error);

			DMibExpectFalse(bValid);
			DMibExpectFalse(Error.f_IsEmpty());
		}

		{
			DMibTestPath("No Certificate Authority");

			NStr::CStr Error;
			bool bValid = CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientCertificateData), {}, false, EVerificationPurpose_Any, {}, nullptr, Error);

			DMibExpectFalse(bValid);
			DMibExpectFalse(Error.f_IsEmpty());
		}

		{
			DMibTestPath("Verification Purpose");

			NStr::CStr Error;

			DMibExpectTrue
				(
					CCertificate::fs_VerifyCertificateChain
					(
						fg_CreateVector(ClientCertificateData)
						, AuthorityCertificateData
						, false
						, EVerificationPurpose_ServerAuth
						, PinnedAnchor
						, nullptr
						, Error
					)
				)
			;
			DMibExpectTrue
				(
					CCertificate::fs_VerifyCertificateChain
					(
						fg_CreateVector(ClientCertificateData)
						, AuthorityCertificateData
						, false
						, EVerificationPurpose_ClientAuth
						, PinnedAnchor
						, nullptr
						, Error
					)
				)
			;

			CByteVector ClientAuthCertificateData;
			CSecureByteVector ClientAuthPrivateKeyData;
			{
				CCertificateOptions ClientAuthOptions;
				ClientAuthOptions.m_CommonName = "Client Auth Only";
				ClientAuthOptions.m_KeySetting = TestKeySetting;

				CByteVector CertificateRequestData;
				CCertificate::fs_GenerateClientCertificateRequest(ClientAuthOptions, CertificateRequestData, ClientAuthPrivateKeyData);

				CCertificateOptions ExtendedKeyUsageOptions;
				ExtendedKeyUsageOptions.f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage_ClientAuth);

				CCertificateSignOptions SignOptions;
				SignOptions.m_Extensions = ExtendedKeyUsageOptions.m_Extensions;

				CCertificate::fs_SignClientCertificate(AuthorityCertificateData, AuthorityPrivateKeyData, CertificateRequestData, ClientAuthCertificateData, SignOptions);
			}

			DMibExpectTrue
				(
					CCertificate::fs_VerifyCertificateChain
					(
						fg_CreateVector(ClientAuthCertificateData)
						, AuthorityCertificateData
						, false
						, EVerificationPurpose_ClientAuth
						, PinnedAnchor
						, nullptr
						, Error
					)
				)
			;
			DMibExpectTrue
				(
					CCertificate::fs_VerifyCertificateChain
					(
						fg_CreateVector(ClientAuthCertificateData)
						, AuthorityCertificateData
						, false
						, EVerificationPurpose_Any
						, PinnedAnchor
						, nullptr
						, Error
					)
				)
			;

			bool bValidAsServer = CCertificate::fs_VerifyCertificateChain
				(
					fg_CreateVector(ClientAuthCertificateData)
					, AuthorityCertificateData
					, false
					, EVerificationPurpose_ServerAuth
					, PinnedAnchor
					, nullptr
					, Error
				)
			;
			DMibExpectFalse(bValidAsServer);
			DMibExpectFalse(Error.f_IsEmpty());

			{
				DMibTestPath("Own Anchor");

				// The store skips purpose checks when the leaf is its own anchor.
				CByteVector SelfSignedClientAuthData;
				CSecureByteVector SelfSignedClientAuthKey;
				{
					CCertificateOptions SelfSignedOptions;
					SelfSignedOptions.m_CommonName = "Self Signed Client Auth Only";
					SelfSignedOptions.m_KeySetting = TestKeySetting;
					SelfSignedOptions.f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage_ClientAuth);

					CCertificate::fs_GenerateSelfSignedCertAndKey(SelfSignedOptions, SelfSignedClientAuthData, SelfSignedClientAuthKey);
				}

				DMibExpectTrue
					(
						CCertificate::fs_VerifyCertificateChain
						(
							fg_CreateVector(SelfSignedClientAuthData)
							, SelfSignedClientAuthData
							, false
							, EVerificationPurpose_ClientAuth
							, {}
							, nullptr
							, Error
						)
					)
				;

				bool bOwnAnchorValidAsServer = CCertificate::fs_VerifyCertificateChain
					(
						fg_CreateVector(SelfSignedClientAuthData)
						, SelfSignedClientAuthData
						, false
						, EVerificationPurpose_ServerAuth
						, {}
						, nullptr
						, Error
					)
				;
				DMibExpectFalse(bOwnAnchorValidAsServer);
				DMibExpectFalse(Error.f_IsEmpty());
			}

			{
				DMibTestPath("Anchor Path Length");

				// The path length of the anchor limits the chain, as BoringSSL checks the anchor.
				auto fMintChain = [&](int32 _RootPathLength, CByteVector &o_LeafData, CByteVector &o_IntermediateData, CByteVector &o_RootData)
					{
						CSecureByteVector RootKeyData;
						{
							CCertificateOptions RootOptions;
							RootOptions.m_CommonName = "Path Length Root";
							RootOptions.m_KeySetting = TestKeySetting;
							RootOptions.f_AddExtension_BasicConstraints(true, true, _RootPathLength);
							RootOptions.f_AddExtension_KeyUsage(EKeyUsage_CertificateSign | EKeyUsage_CRLSign);
							CCertificate::fs_GenerateSelfSignedCertAndKey(RootOptions, o_RootData, RootKeyData);
						}

						// The request's CA:TRUE is copied verbatim because the sign options carry
						// no leaf role and no extension whitelist
						CSecureByteVector IntermediateKeyData;
						{
							CCertificateOptions IntermediateOptions;
							IntermediateOptions.m_CommonName = "Intermediate";
							IntermediateOptions.m_KeySetting = TestKeySetting;
							IntermediateOptions.f_AddExtension_BasicConstraints(true);
							IntermediateOptions.f_AddExtension_KeyUsage(EKeyUsage_CertificateSign);

							CByteVector RequestData;
							CCertificate::fs_GenerateClientCertificateRequest(IntermediateOptions, RequestData, IntermediateKeyData);
							CCertificate::fs_SignClientCertificate(o_RootData, RootKeyData, RequestData, o_IntermediateData);
						}

						CSecureByteVector LeafKeyData;
						{
							CCertificateOptions LeafOptions;
							LeafOptions.m_CommonName = "Leaf Under Intermediate";
							LeafOptions.m_KeySetting = TestKeySetting;

							CByteVector RequestData;
							CCertificate::fs_GenerateClientCertificateRequest(LeafOptions, RequestData, LeafKeyData);
							CCertificate::fs_SignClientCertificate(o_IntermediateData, IntermediateKeyData, RequestData, o_LeafData);
						}
					}
				;

				CByteVector LeafData;
				CByteVector IntermediateData;
				CByteVector RootData;
				fMintChain(0, LeafData, IntermediateData, RootData);

				bool bPathLenValid = CCertificate::fs_VerifyCertificateChain(fg_CreateVector(LeafData, IntermediateData), RootData, false, EVerificationPurpose_Any, {}, nullptr, Error);
				DMibExpectFalse(bPathLenValid);
				DMibExpect(Error, ==, CStr("path length constraint exceeded"));

				fMintChain(1, LeafData, IntermediateData, RootData);
				DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(LeafData, IntermediateData), RootData, false, EVerificationPurpose_Any, {}, nullptr, Error));
			}

			{
				DMibTestPath("Key Usage Must Allow Signing");

				CByteVector KeyExchangeOnlyData;
				CSecureByteVector KeyExchangeOnlyKey;
				{
					CCertificateOptions KeyExchangeOnlyOptions;
					KeyExchangeOnlyOptions.m_CommonName = "Key Exchange Only";
					KeyExchangeOnlyOptions.m_KeySetting = TestKeySetting;
					KeyExchangeOnlyOptions.f_AddExtension_KeyUsage(EKeyUsage_KeyEncipherment);

					CCertificate::fs_GenerateSelfSignedCertAndKey(KeyExchangeOnlyOptions, KeyExchangeOnlyData, KeyExchangeOnlyKey);
				}

				DMibExpectFalse
					(
						CCertificate::fs_VerifyCertificateChain(fg_CreateVector(KeyExchangeOnlyData), KeyExchangeOnlyData, false, EVerificationPurpose_ServerAuth, {}, nullptr, Error)
					)
				;
				DMibExpectFalse
					(
						CCertificate::fs_VerifyCertificateChain(fg_CreateVector(KeyExchangeOnlyData), KeyExchangeOnlyData, false, EVerificationPurpose_ClientAuth, {}, nullptr, Error)
					)
				;
				DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(KeyExchangeOnlyData), KeyExchangeOnlyData, false, EVerificationPurpose_Any, {}, nullptr, Error));
			}
		}

		{
			DMibTestPath("Pinned Leaf Anchor");

			NStr::CStr Error;
			DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientCertificateData), ClientCertificateData, false, EVerificationPurpose_Any, {}, nullptr, Error));
		}

		{
			DMibTestPath("Pinned Leaf With Unsupported Critical Extension");

			// The verifier must reject an unknown critical extension even on a directly pinned leaf.
			CCertificate::fs_RegisterExtension("1.3.6.1.4.1.47722.1.3", "MalterlibTestCritical", "Malterlib Test Critical");

			CPublicKeySetting CriticalKeySetting = CPublicKeySettings_EC_Secp256r1{};

			auto fGenerate = [&](bool _bCritical, CByteVector &o_CertificateData)
				{
					CSecureByteVector Key;
					CCertificateOptions Options;
					Options.m_CommonName = "CriticalExtension";
					Options.m_KeySetting = CriticalKeySetting;

					auto &Extension = Options.m_Extensions["MalterlibTestCritical"].f_Insert();
					Extension.m_Value = "Critical";
					Extension.m_bCritical = _bCritical;

					CCertificate::fs_GenerateSelfSignedCertAndKey(Options, o_CertificateData, Key);
				}
			;

			CByteVector CriticalCertificateData;
			fGenerate(true, CriticalCertificateData);

			NStr::CStr Error;
			DMibExpectFalse(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(CriticalCertificateData), CriticalCertificateData, false, EVerificationPurpose_Any, {}, nullptr, Error));
			DMibExpect(Error, ==, "Certificate contains an unsupported critical extension");

			CByteVector NonCriticalCertificateData;
			fGenerate(false, NonCriticalCertificateData);

			Error.f_Clear();
			DMibExpectTrue
				(
					CCertificate::fs_VerifyCertificateChain(fg_CreateVector(NonCriticalCertificateData), NonCriticalCertificateData, false, EVerificationPurpose_Any, {}, nullptr, Error)
				)
			;
		}

		{
			DMibTestPath("Anchor Critical Extension");

			// The exact error distinguishes the anchor-extension check from leaf validation.
			auto fMint = [&](bool _bCritical, CByteVector &o_LeafData, CByteVector &o_RootData)
				{
					CSecureByteVector RootKey;
					{
						CCertificateOptions RootOptions;
						RootOptions.m_CommonName = "Critical Extension Root";
						RootOptions.m_KeySetting = TestKeySetting;

						auto &Extension = RootOptions.m_Extensions["MalterlibTestCritical"].f_Insert();
						Extension.m_Value = "Critical";
						Extension.m_bCritical = _bCritical;

						CCertificate::fs_GenerateSelfSignedCertAndKey(RootOptions, o_RootData, RootKey);
					}

					CSecureByteVector LeafKey;
					{
						CCertificateOptions LeafOptions;
						LeafOptions.m_CommonName = "Leaf Under Critical Root";
						LeafOptions.m_KeySetting = TestKeySetting;

						CByteVector RequestData;
						CCertificate::fs_GenerateClientCertificateRequest(LeafOptions, RequestData, LeafKey);
						CCertificate::fs_SignClientCertificate(o_RootData, RootKey, RequestData, o_LeafData);
					}
				}
			;

			CByteVector LeafData;
			CByteVector RootData;
			fMint(true, LeafData, RootData);

			NStr::CStr Error;
			DMibExpectFalse(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(LeafData), RootData, false, EVerificationPurpose_Any, PinnedAnchor, nullptr, Error));
			DMibExpect(Error, ==, CStr("unhandled critical extension"));

			fMint(false, LeafData, RootData);
			DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(LeafData), RootData, false, EVerificationPurpose_Any, PinnedAnchor, nullptr, Error));
		}

		{
			DMibTestPath("Intermediate Signature Digest Whitelist");

			CByteVector RootData;
			CSecureByteVector RootKeyData;
			{
				CCertificateOptions RootOptions;
				RootOptions.m_CommonName = "Digest Root";
				RootOptions.m_KeySetting = TestKeySetting;
				RootOptions.f_AddExtension_BasicConstraints(true);
				RootOptions.f_AddExtension_KeyUsage(EKeyUsage_CertificateSign | EKeyUsage_CRLSign);
				CCertificate::fs_GenerateSelfSignedCertAndKey(RootOptions, RootData, RootKeyData);
			}

			CByteVector IntermediateData;
			CSecureByteVector IntermediateKeyData;
			{
				CCertificateOptions IntermediateOptions;
				IntermediateOptions.m_CommonName = "Digest Intermediate";
				IntermediateOptions.m_KeySetting = TestKeySetting;
				IntermediateOptions.f_AddExtension_BasicConstraints(true);
				IntermediateOptions.f_AddExtension_KeyUsage(EKeyUsage_CertificateSign);

				CByteVector RequestData;
				CCertificate::fs_GenerateClientCertificateRequest(IntermediateOptions, RequestData, IntermediateKeyData);
				CCertificate::fs_SignClientCertificate(RootData, RootKeyData, RequestData, IntermediateData);
			}

			CByteVector LeafData;
			{
				CCertificateOptions LeafOptions;
				LeafOptions.m_CommonName = "Digest Leaf";
				LeafOptions.m_KeySetting = TestKeySetting;

				CSecureByteVector LeafKeyData;
				CByteVector RequestData;
				CCertificate::fs_GenerateClientCertificateRequest(LeafOptions, RequestData, LeafKeyData);
				CCertificate::fs_SignClientCertificate(IntermediateData, IntermediateKeyData, RequestData, LeafData);
			}

			// Re-sign only the intermediate with another digest; its key is unchanged, so the leaf still chains to it
			{
				X509 *pIntermediate = NBoringSSL::fg_LoadCertificate(IntermediateData);
				auto CleanupCert = g_OnScopeExit / [&]
					{
						X509_free(pIntermediate);
					}
				;

				EVP_PKEY *pRootKey = NBoringSSL::fg_LoadPrivateKey(RootKeyData);
				auto CleanupKey = g_OnScopeExit / [&]
					{
						EVP_PKEY_free(pRootKey);
					}
				;

				DMibExpectTrue(X509_sign(pIntermediate, pRootKey, EVP_sha512()) > 0);
				IntermediateData = NBoringSSL::fg_ConvertX509ToBinary(pIntermediate);
			}

			CCertificateVerifyOptions LeafDigestOnly;
			LeafDigestOnly.m_AllowedSignatureDigests.f_Insert(EDigestType_SHA256);
			NStr::CStr Error;
			bool bLeafDigestOnlyValid = CCertificate::fs_VerifyCertificateChain
				(
					fg_CreateVector(LeafData, IntermediateData)
					, RootData
					, false
					, EVerificationPurpose_Any
					, LeafDigestOnly
					, nullptr
					, Error
				)
			;
			DMibExpectFalse(bLeafDigestOnlyValid);
			DMibExpect(Error, ==, CStr("Certificate chain signature digest is not allowed"));

			CCertificateVerifyOptions BothDigests;
			BothDigests.m_AllowedSignatureDigests.f_Insert(EDigestType_SHA256);
			BothDigests.m_AllowedSignatureDigests.f_Insert(EDigestType_SHA512);
			bool bBothDigestsValid = CCertificate::fs_VerifyCertificateChain
				(
					fg_CreateVector(LeafData, IntermediateData)
					, RootData
					, false
					, EVerificationPurpose_Any
					, BothDigests
					, nullptr
					, Error
				)
			;
			DMibExpectTrue(bBothDigestsValid);
		}

		{
			DMibTestPath("Anchor Extended Key Usage");

			CByteVector RootData;
			CSecureByteVector RootKeyData;
			{
				CCertificateOptions RootOptions;
				RootOptions.m_CommonName = "EKU Root";
				RootOptions.m_KeySetting = TestKeySetting;
				RootOptions.f_AddExtension_BasicConstraints(true);
				RootOptions.f_AddExtension_KeyUsage(EKeyUsage_CertificateSign | EKeyUsage_CRLSign);
				CCertificate::fs_GenerateSelfSignedCertAndKey(RootOptions, RootData, RootKeyData);
			}

			// The intermediate may only issue client certificates
			CByteVector IntermediateData;
			CSecureByteVector IntermediateKeyData;
			{
				CCertificateOptions IntermediateOptions;
				IntermediateOptions.m_CommonName = "Client Auth Intermediate";
				IntermediateOptions.m_KeySetting = TestKeySetting;
				IntermediateOptions.f_AddExtension_BasicConstraints(true);
				IntermediateOptions.f_AddExtension_KeyUsage(EKeyUsage_CertificateSign);
				IntermediateOptions.f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage_ClientAuth);

				CByteVector RequestData;
				CCertificate::fs_GenerateClientCertificateRequest(IntermediateOptions, RequestData, IntermediateKeyData);
				CCertificate::fs_SignClientCertificate(RootData, RootKeyData, RequestData, IntermediateData);
			}

			CByteVector ServerData;
			{
				CCertificateOptions ServerOptions;
				ServerOptions.m_CommonName = "Server Under Client Auth Intermediate";
				ServerOptions.m_KeySetting = TestKeySetting;

				CSecureByteVector ServerKeyData;
				CByteVector RequestData;
				CCertificate::fs_GenerateClientCertificateRequest(ServerOptions, RequestData, ServerKeyData);
				CCertificate::fs_SignClientCertificate(IntermediateData, IntermediateKeyData, RequestData, ServerData);
			}

			NStr::CStr Error;
			bool bValidThroughRoot = CCertificate::fs_VerifyCertificateChain
				(
					fg_CreateVector(ServerData, IntermediateData)
					, RootData
					, false
					, EVerificationPurpose_ServerAuth
					, {}
					, nullptr
					, Error
				)
			;
			DMibExpectFalse(bValidThroughRoot);

			// Handing the intermediate over as the anchor must not shed its restriction
			bool bValidFromIntermediate = CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ServerData), IntermediateData, false, EVerificationPurpose_ServerAuth, {}, nullptr, Error);
			DMibExpectFalse(bValidFromIntermediate);
			DMibExpect(Error, ==, CStr("unsupported certificate purpose"));

			bool bValidForAny = CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ServerData), IntermediateData, false, EVerificationPurpose_Any, {}, nullptr, Error);
			DMibExpectTrue(bValidForAny);
		}

		{
			DMibTestPath("RSA-PSS Signature Digest Whitelist");

			// RSASSA-PSS identifies its digest in parameters, not in the signature OID.
			CByteVector RsaCertData;
			CSecureByteVector RsaKeyData;
			{
				CCertificateOptions RsaOptions;
				RsaOptions.m_CommonName = "PSS Test";
				RsaOptions.m_KeySetting = CPublicKeySettings_RSA{2048};
				CCertificate::fs_GenerateSelfSignedCertAndKey(RsaOptions, RsaCertData, RsaKeyData);
			}

			CByteVector PssCertData;
			{
				X509 *pCert = NBoringSSL::fg_LoadCertificate(RsaCertData);
				auto CleanupCert = g_OnScopeExit / [&]
					{
						X509_free(pCert);
					}
				;

				EVP_PKEY *pKey = NBoringSSL::fg_LoadPrivateKey(RsaKeyData);
				auto CleanupKey = g_OnScopeExit / [&]
					{
						EVP_PKEY_free(pKey);
					}
				;

				EVP_MD_CTX *pMdCtx = EVP_MD_CTX_new();
				auto CleanupMdCtx = g_OnScopeExit / [&]
					{
						EVP_MD_CTX_free(pMdCtx);
					}
				;

				EVP_PKEY_CTX *pKeyCtx = nullptr;
				DMibExpectTrue(EVP_DigestSignInit(pMdCtx, &pKeyCtx, EVP_sha256(), nullptr, pKey) == 1);
				DMibExpectTrue(EVP_PKEY_CTX_set_rsa_padding(pKeyCtx, RSA_PKCS1_PSS_PADDING) == 1);
				DMibExpectTrue(X509_sign_ctx(pCert, pMdCtx) > 0);

				PssCertData = NBoringSSL::fg_ConvertX509ToBinary(pCert);
			}

			NStr::CStr Error;

			CCertificateVerifyOptions AllowedOptions;
			AllowedOptions.m_AllowedSignatureDigests.f_Insert(EDigestType_SHA256);
			DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(PssCertData), PssCertData, false, EVerificationPurpose_Any, AllowedOptions, nullptr, Error));

			CCertificateVerifyOptions WrongDigestOptions;
			WrongDigestOptions.m_AllowedSignatureDigests.f_Insert(EDigestType_SHA512);
			DMibExpectFalse(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(PssCertData), PssCertData, false, EVerificationPurpose_Any, WrongDigestOptions, nullptr, Error));
			DMibExpect(Error, ==, CStr("Certificate signature digest is not allowed"));
		}

		{
			DMibTestPath("Key Type And Digest Whitelist");

			CCertificateVerifyOptions MatchingOptions;
			MatchingOptions.m_bAllowPinnedTrustAnchor = true;
			MatchingOptions.m_AllowedLeafKeyTypes.f_Insert(CPublicKeySettings_EC_Secp256r1{});
			MatchingOptions.m_AllowedSignatureDigests.f_Insert(EDigestType_SHA256);

			NStr::CStr Error;
			DMibExpectTrue
				(
					CCertificate::fs_VerifyCertificateChain
					(
						fg_CreateVector(ClientCertificateData)
						, AuthorityCertificateData
						, false
						, EVerificationPurpose_Any
						, MatchingOptions
						, nullptr
						, Error
					)
				)
			;

			CCertificateVerifyOptions WrongKeyType;
			WrongKeyType.m_bAllowPinnedTrustAnchor = true;
			WrongKeyType.m_AllowedLeafKeyTypes.f_Insert(CPublicKeySettings_EC_Secp521r1{});
			DMibExpectFalse
				(
					CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientCertificateData), AuthorityCertificateData, false, EVerificationPurpose_Any, WrongKeyType, nullptr, Error)
				)
			;
			DMibExpect(Error, ==, CStr("Certificate public key type is not allowed"));

			CCertificateVerifyOptions WrongDigest;
			WrongDigest.m_bAllowPinnedTrustAnchor = true;
			WrongDigest.m_AllowedSignatureDigests.f_Insert(EDigestType_SHA512);
			DMibExpectFalse
				(
					CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientCertificateData), AuthorityCertificateData, false, EVerificationPurpose_Any, WrongDigest, nullptr, Error)
				)
			;
			DMibExpect(Error, ==, CStr("Certificate signature digest is not allowed"));
		}

		{
			DMibTestPath("Verified Chain Excludes Unrelated Certificates");

			CByteVector UnrelatedCertificateData;
			CSecureByteVector UnrelatedKey;
			{
				CCertificateOptions UnrelatedOptions;
				UnrelatedOptions.m_CommonName = "Unrelated";
				UnrelatedOptions.m_KeySetting = TestKeySetting;

				CCertificate::fs_GenerateSelfSignedCertAndKey(UnrelatedOptions, UnrelatedCertificateData, UnrelatedKey);
			}

			NStr::CStr Error;
			TCVector<CByteVector> VerifiedChain;
			bool bValid = CCertificate::fs_VerifyCertificateChain
				(
					fg_CreateVector(ClientCertificateData, UnrelatedCertificateData)
					, AuthorityCertificateData
					, false
					, EVerificationPurpose_Any
					, PinnedAnchor
					, &VerifiedChain
					, Error
				)
			;

			DMibExpectTrue(bValid);

			DMibExpect(VerifiedChain.f_GetLen(), ==, umint(2));

			CStr UnrelatedFingerprint = CCertificate::fs_GetCertificateFingerprint(UnrelatedCertificateData);
			for (umint iCertificate = 0; iCertificate < VerifiedChain.f_GetLen(); ++iCertificate)
			{
				DMibTestPath("{}"_f << iCertificate);
				DMibExpect(CCertificate::fs_GetCertificateFingerprint(VerifiedChain[iCertificate]), !=, UnrelatedFingerprint);
			}
		}

		{
			DMibTestPath("Certificate Public Key Verifies Signature");

			CSecureByteVector ClientPrivateKeyDER;
			{
				EVP_PKEY *pKey = NBoringSSL::fg_LoadPrivateKey(ClientPrivateKeyData);
				auto Cleanup = g_OnScopeExit / [&]
					{
						EVP_PKEY_free(pKey);
					}
				;

				ClientPrivateKeyDER = NBoringSSL::fg_ConvertPrivateKeyToDER(pKey);
			}

			CSecureByteVector Message;
			Message.f_InsertLast((uint8 const *)"Test message", 12);

			auto Signature = CPublicCrypto::fs_SignMessage(Message, ClientPrivateKeyDER);
			auto PublicKey = CCertificate::fs_GetCertificatePublicKey(ClientCertificateData);

			DMibExpectTrue(CPublicCrypto::fs_VerifySignature(Message, PublicKey, Signature));

			CSecureByteVector OtherMessage;
			OtherMessage.f_InsertLast((uint8 const *)"Other message", 13);

			DMibExpectFalse(CPublicCrypto::fs_VerifySignature(OtherMessage, PublicKey, Signature));
		}
	};
}

DMibTestRegister(CCertificate_Tests, Malterlib::Cryptography);
