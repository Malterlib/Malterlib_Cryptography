// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Network/SSL>
#include <Mib/Test/Exception>
#include <Mib/Cryptography/Certificate>
#include <Mib/Cryptography/SymmetricCrypto>
#include <Mib/Cryptography/PublicCrypto>
#include <Mib/Cryptography/BoringSSL>

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
			CPublicKeySetting TestKeySetting = CPublicKeySettings_EC_secp256r1{};

			// The self-signed certificate goes directly into the verification store, which makes it an
			// explicit trust anchor; anchors do not need basicConstraints CA:TRUE for path building, so
			// no f_MakeCA is required here
			CByteVector CACertificateData;
			CSecureByteVector CAPrivateKeyData;
			CCertificateOptions CAOptions;
			CAOptions.m_CommonName = "Test CA";
			CAOptions.m_KeySetting = TestKeySetting;
			CCertificate::fs_GenerateSelfSignedCertAndKey(CAOptions, CACertificateData, CAPrivateKeyData);

			CByteVector ClientCertificateData;
			CSecureByteVector ClientPrivateKeyData;
			{
				CCertificateOptions ClientOptions;
				ClientOptions.m_CommonName = "Test Client";
				ClientOptions.m_KeySetting = TestKeySetting;

				CByteVector CertificateRequestData;
				CCertificate::fs_GenerateClientCertificateRequest(ClientOptions, CertificateRequestData, ClientPrivateKeyData);
				CCertificate::fs_SignClientCertificate(CACertificateData, CAPrivateKeyData, CertificateRequestData, ClientCertificateData);
			}

			{
				DMibTestPath("Valid Chain");

				NStr::CStr Error;
				TCVector<CByteVector> VerifiedChain;
				bool bValid = CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientCertificateData), CACertificateData, false, EVerificationPurpose_Any, {}, &VerifiedChain, Error);

				DMibExpectTrue(bValid);
				DMibExpect(Error, ==, CStr());

				// The verified path runs from the leaf up to the trust anchor
				DMibExpect(VerifiedChain.f_GetLen(), ==, umint(2));
				DMibExpect(CCertificate::fs_GetCertificateFingerprint(VerifiedChain[0]), ==, CCertificate::fs_GetCertificateFingerprint(ClientCertificateData));
				DMibExpect(CCertificate::fs_GetCertificateFingerprint(VerifiedChain[1]), ==, CCertificate::fs_GetCertificateFingerprint(CACertificateData));
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
				bool bValid = CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientCertificateData), OtherCACertificateData, false, EVerificationPurpose_Any, {}, nullptr, Error);

				DMibExpectFalse(bValid);
				DMibExpectFalse(Error.f_IsEmpty());
			}

			{
				DMibTestPath("Empty Chain");

				NStr::CStr Error;
				bool bValid = CCertificate::fs_VerifyCertificateChain({}, CACertificateData, false, EVerificationPurpose_Any, {}, nullptr, Error);

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

				// A certificate with no extended key usage satisfies any purpose, so the existing client
				// certificate (which sets no EKU) verifies for both roles. This keeps the purpose check
				// from rejecting certificates that carry no role separation
				DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientCertificateData), CACertificateData, false, EVerificationPurpose_ServerAuth, {}, nullptr, Error));
				DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientCertificateData), CACertificateData, false, EVerificationPurpose_ClientAuth, {}, nullptr, Error));

				// A certificate that does carry an extended key usage must include the requested role: a
				// clientAuth only certificate verifies as a client but is rejected as a server
				CByteVector ClientAuthCertificateData;
				CSecureByteVector ClientAuthPrivateKeyData;
				{
					CCertificateOptions ClientAuthOptions;
					ClientAuthOptions.m_CommonName = "Client Auth Only";
					ClientAuthOptions.m_KeySetting = TestKeySetting;

					CByteVector CertificateRequestData;
					CCertificate::fs_GenerateClientCertificateRequest(ClientAuthOptions, CertificateRequestData, ClientAuthPrivateKeyData);

					// The issuer restricts the certificate to clientAuth
					CCertificateOptions ExtendedKeyUsageOptions;
					ExtendedKeyUsageOptions.f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage_ClientAuth);

					CCertificateSignOptions SignOptions;
					SignOptions.m_Extensions = ExtendedKeyUsageOptions.m_Extensions;

					CCertificate::fs_SignClientCertificate(CACertificateData, CAPrivateKeyData, CertificateRequestData, ClientAuthCertificateData, SignOptions);
				}

				DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientAuthCertificateData), CACertificateData, false, EVerificationPurpose_ClientAuth, {}, nullptr, Error));
				DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientAuthCertificateData), CACertificateData, false, EVerificationPurpose_Any, {}, nullptr, Error));

				bool bValidAsServer = CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientAuthCertificateData), CACertificateData, false, EVerificationPurpose_ServerAuth, {}, nullptr, Error);
				DMibExpectFalse(bValidAsServer);
				DMibExpectFalse(Error.f_IsEmpty());

				{
					DMibTestPath("Own Anchor");

					// The purpose must also hold when the pinned anchor is the leaf itself: path
					// building substitutes the trusted store copy for the leaf and skips it in the
					// store context purpose check, so the direct leaf check has to catch the mismatch
					CByteVector SelfSignedClientAuthData;
					CSecureByteVector SelfSignedClientAuthKey;
					{
						CCertificateOptions SelfSignedOptions;
						SelfSignedOptions.m_CommonName = "Self Signed Client Auth Only";
						SelfSignedOptions.m_KeySetting = TestKeySetting;
						SelfSignedOptions.f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage_ClientAuth);

						CCertificate::fs_GenerateSelfSignedCertAndKey(SelfSignedOptions, SelfSignedClientAuthData, SelfSignedClientAuthKey);
					}

					DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(SelfSignedClientAuthData), SelfSignedClientAuthData, false, EVerificationPurpose_ClientAuth, {}, nullptr, Error));

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

					// A root pinned as the trust anchor with pathlen:0 must reject any chain that
					// puts an intermediate CA below it. BoringSSL's path length checking iterates
					// only the untrusted certificates and never consults the anchor's own
					// constraint, so the rejection must come from fs_VerifyCertificateChain's
					// explicit anchor check: asserting its exact error proves both that the chain is
					// rejected and that the store context passed it
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
					DMibExpect(Error, ==, CStr("Certificate chain is longer than the trust anchor's path length constraint allows"));

					// The identical structure verifies under a pathlen:1 root, so the constraint is
					// what rejected it, not the chain construction
					fMintChain(1, LeafData, IntermediateData, RootData);
					DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(LeafData, IntermediateData), RootData, false, EVerificationPurpose_Any, {}, nullptr, Error));
				}

				{
					DMibTestPath("Key Usage Must Allow Signing");

					// Both roles authenticate by signing, so a key usage extension limited to key
					// exchange fails the role purposes even though TLS purposes alone would accept it;
					// without a requested purpose no role checks apply
					CByteVector KeyExchangeOnlyData;
					CSecureByteVector KeyExchangeOnlyKey;
					{
						CCertificateOptions KeyExchangeOnlyOptions;
						KeyExchangeOnlyOptions.m_CommonName = "Key Exchange Only";
						KeyExchangeOnlyOptions.m_KeySetting = TestKeySetting;
						KeyExchangeOnlyOptions.f_AddExtension_KeyUsage(EKeyUsage_KeyEncipherment);

						CCertificate::fs_GenerateSelfSignedCertAndKey(KeyExchangeOnlyOptions, KeyExchangeOnlyData, KeyExchangeOnlyKey);
					}

					DMibExpectFalse(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(KeyExchangeOnlyData), KeyExchangeOnlyData, false, EVerificationPurpose_ServerAuth, {}, nullptr, Error));
					DMibExpectFalse(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(KeyExchangeOnlyData), KeyExchangeOnlyData, false, EVerificationPurpose_ClientAuth, {}, nullptr, Error));
					DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(KeyExchangeOnlyData), KeyExchangeOnlyData, false, EVerificationPurpose_Any, {}, nullptr, Error));
				}
			}

			{
				DMibTestPath("Pinned Leaf Anchor");

				// A CA-issued certificate pinned directly is an explicit trust anchor even though it is
				// not self-signed; path building stops at the store match instead of requiring a root
				NStr::CStr Error;
				DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientCertificateData), ClientCertificateData, false, EVerificationPurpose_Any, {}, nullptr, Error));
			}

			{
				DMibTestPath("Pinned Leaf With Unsupported Critical Extension");

				// The store context skips the unhandled-critical-extension check for a leaf that is
				// its own trust anchor, so the direct leaf validation must reject it; the registered
				// test extension is unknown to the verifier and marking it critical must fail even
				// with EVerificationPurpose_Any while the non-critical variant verifies. The
				// registration uses its own OID so this suite does not depend on another suite
				// having run in the same process
				CCertificate::fs_RegisterExtension
					(
						"1.3.6.1.4.1.47722.1.3"
						, "MalterlibTestCritical"
						, "Malterlib Test Critical"
					)
				;

				CPublicKeySetting CriticalKeySetting = CPublicKeySettings_EC_secp256r1{};

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
				DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(NonCriticalCertificateData), NonCriticalCertificateData, false, EVerificationPurpose_Any, {}, nullptr, Error));
			}

			{
				DMibTestPath("Anchor Critical Extension");

				// The store context never examines a distinct trust anchor's extensions, so the
				// explicit anchor check must reject a pinned CA carrying an unrecognized critical
				// extension; the exact error proves the rejection comes from the anchor check and
				// not from the leaf checks
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
				DMibExpectFalse(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(LeafData), RootData, false, EVerificationPurpose_Any, {}, nullptr, Error));
				DMibExpect(Error, ==, CStr("Trust anchor contains an unsupported critical extension"));

				// The non-critical variant verifies, so the critical marking is what rejected it
				fMint(false, LeafData, RootData);
				DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(LeafData), RootData, false, EVerificationPurpose_Any, {}, nullptr, Error));
			}

			{
				DMibTestPath("RSA-PSS Signature Digest Whitelist");

				// A signature digest whitelist must read the hash from the RSASSA-PSS parameters: the
				// signature OID for PSS only names rsassaPss and does not itself identify the digest.
				// Manufacture a PSS-signed certificate and confirm the whitelist accepts its actual
				// digest (SHA-256) and rejects a different one
				CByteVector RsaCertData;
				CSecureByteVector RsaKeyData;
				{
					CCertificateOptions RsaOptions;
					RsaOptions.m_CommonName = "PSS Test";
					RsaOptions.m_KeySetting = CPublicKeySettings_RSA{2048};
					CCertificate::fs_GenerateSelfSignedCertAndKey(RsaOptions, RsaCertData, RsaKeyData);
				}

				// Replace the certificate's PKCS#1 v1.5 signature with an RSASSA-PSS/SHA-256 one
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

				// The EC path exercises fg_GetSignatureDigestNID's non-PSS branch and the leaf key
				// type whitelist: a secp256r1/SHA-256 leaf is accepted by matching options and
				// rejected when the whitelist names a different curve or digest
				CCertificateVerifyOptions MatchingOptions;
				MatchingOptions.m_AllowedLeafKeyTypes.f_Insert(CPublicKeySettings_EC_secp256r1{});
				MatchingOptions.m_AllowedSignatureDigests.f_Insert(EDigestType_SHA256);

				NStr::CStr Error;
				DMibExpectTrue(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientCertificateData), CACertificateData, false, EVerificationPurpose_Any, MatchingOptions, nullptr, Error));

				CCertificateVerifyOptions WrongKeyType;
				WrongKeyType.m_AllowedLeafKeyTypes.f_Insert(CPublicKeySettings_EC_secp521r1{});
				DMibExpectFalse(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientCertificateData), CACertificateData, false, EVerificationPurpose_Any, WrongKeyType, nullptr, Error));
				DMibExpect(Error, ==, CStr("Certificate public key type is not allowed"));

				CCertificateVerifyOptions WrongDigest;
				WrongDigest.m_AllowedSignatureDigests.f_Insert(EDigestType_SHA512);
				DMibExpectFalse(CCertificate::fs_VerifyCertificateChain(fg_CreateVector(ClientCertificateData), CACertificateData, false, EVerificationPurpose_Any, WrongDigest, nullptr, Error));
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
						, CACertificateData
						, false
						, EVerificationPurpose_Any
						, {}
						, &VerifiedChain
						, Error
					)
				;

				DMibExpectTrue(bValid);

				// The unrelated extra certificate from the wire list is not part of the verified path
				DMibExpect(VerifiedChain.f_GetLen(), ==, umint(2));

				CStr UnrelatedFingerprint = CCertificate::fs_GetCertificateFingerprint(UnrelatedCertificateData);
				for (umint i = 0; i < VerifiedChain.f_GetLen(); ++i)
				{
					DMibTestPath("{}"_f << i);
					DMibExpect(CCertificate::fs_GetCertificateFingerprint(VerifiedChain[i]), !=, UnrelatedFingerprint);
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
};

DMibTestRegister(CCertificate_Tests, Malterlib::Crytpography);
