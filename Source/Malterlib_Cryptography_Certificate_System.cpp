// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Cryptography_Certificate.h"

#include <Mib/Cryptography/BoringSSL>
#include <Mib/Encoding/Base64>

#if defined(DPlatformFamily_macOS)
	#include <Security/Security.h>
#elif defined(DPlatformFamily_Windows)
	#include <Windows.h>
	#include <Wincrypt.h>

	#undef X509_NAME
	#undef X509_EXTENSIONS
	#undef PKCS7_ISSUER_AND_SERIAL
	#undef OCSP_REQUEST
	#undef OCSP_RESPONSE

	#pragma comment(lib, "crypt32.lib")
#endif

namespace NMib::NCryptography
{
	using namespace NBoringSSL;

	namespace
	{
		struct CCertificateGlobals
		{
			CCertificateGlobals()
			{
				NBoringSSL::fg_Init();
			}

			~CCertificateGlobals()
			{
				if (m_pSystemCertStore)
					X509_STORE_free(m_pSystemCertStore);
			}

			NMib::NThread::CMutual m_SystemCertStoreLock;
			X509_STORE *m_pSystemCertStore = nullptr;
		};

		constinit NStorage::TCAggregate<CCertificateGlobals, 129> g_CertificateGlobals = {DAggregateInit};
	}

	namespace
	{
#if defined(DPlatformFamily_Windows)
		X509_STORE *fg_ExtractSystemCertificates()
		{
			auto pStore = X509_STORE_new();
			auto Now = NTime::CTime::fs_NowUTC();

			auto fIsPKCS7 = [](DWORD _EncodeType)
				{
					return ((_EncodeType & PKCS_7_ASN_ENCODING) == PKCS_7_ASN_ENCODING);
				}
			;

			auto fLoadFromStore = [&] (LPCWSTR _pStore)
			{
				HCERTSTORE hStore = CertOpenSystemStore(NULL, _pStore);
				for (PCCERT_CONTEXT pCertContext = CertEnumCertificatesInStore(hStore, nullptr); pCertContext; pCertContext = CertEnumCertificatesInStore(hStore, pCertContext))
				{
					NStr::CStr OutputType = fIsPKCS7(pCertContext->dwCertEncodingType) ? "PKCS7" : "CERTIFICATE";
					NContainer::CByteVector Data;
					Data.f_Insert(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
					NStr::CStr CertData = NEncoding::fg_Base64Encode(Data);
					NStr::CStr CertAsString = NStr::CStr::CFormat("-----BEGIN {}-----\n{}\n-----END {}-----\n") << OutputType << CertData << OutputType;

					NContainer::CByteVector lCertData;
					lCertData.f_SetLen(CertAsString.f_GetLen());
					NMemory::fg_MemCopy(lCertData.f_GetArray(), CertAsString.f_GetStr(), CertAsString.f_GetLen());

					X509 *pCertificate;
					try
					{
						pCertificate = fg_LoadCertificate(lCertData);
					}
					catch (CExceptionCryptography const &)
					{
						continue;
					}
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_free(pCertificate);
						}
					;

					if (fg_GetX509ExpireTime(pCertificate) > Now)
						X509_STORE_add_cert(pStore, pCertificate);
				}

				for (PCCRL_CONTEXT pCrlContext = CertEnumCRLsInStore(hStore, nullptr); pCrlContext; pCrlContext = CertEnumCRLsInStore(hStore, pCrlContext))
				{
					NStr::CStr OutputType = fIsPKCS7(pCrlContext->dwCertEncodingType) ? "PKCS7" : "X509 CRL";
					NContainer::CByteVector Data;
					Data.f_Insert(pCrlContext->pbCrlEncoded, pCrlContext->cbCrlEncoded);
					NStr::CStr CertData = NEncoding::fg_Base64Encode(Data);
					NStr::CStr CertAsString = NStr::CStr::CFormat("-----BEGIN {}-----\n{}\n-----END {}-----\n") << OutputType << CertData << OutputType;

					NContainer::CByteVector lCertData;
					lCertData.f_SetLen(CertAsString.f_GetLen());
					NMemory::fg_MemCopy(lCertData.f_GetArray(), CertAsString.f_GetStr(), CertAsString.f_GetLen());

					X509_CRL *pCrl;
					try
					{
						pCrl = fg_LoadCrl(lCertData);
					}
					catch (CExceptionCryptography const &)
					{
						continue;
					}
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_CRL_free(pCrl);
						}
					;

					X509_STORE_add_crl(pStore, pCrl);
				}

				CertCloseStore(hStore, 0);
			};

			fLoadFromStore(L"ROOT");
			fLoadFromStore(L"CA");

			return pStore;
		}

#elif defined(DPlatformFamily_macOS)

		X509_STORE *fg_ExtractSystemCertificates()
		{
			auto Now = NTime::CTime::fs_NowUTC();

			auto pStore = X509_STORE_new();

			NContainer::TCSet<NContainer::CByteVector> Untrusted;
			NContainer::TCSet<NContainer::CByteVector> Trusted;

			auto fCheckTrust10_7 = [](SecCertificateRef _pCertRef) -> SecTrustSettingsResult
				{
					CFArrayRef pTrustSettings = nullptr;
					if (SecTrustSettingsCopyTrustSettings(_pCertRef, kSecTrustSettingsDomainUser, &pTrustSettings) != 0)
					{
						if (SecTrustSettingsCopyTrustSettings(_pCertRef, kSecTrustSettingsDomainAdmin, &pTrustSettings) != 0)
							return kSecTrustSettingsResultUnspecified;
					}

					if (!pTrustSettings)
						return kSecTrustSettingsResultUnspecified;

					auto CleanupTrust = g_OnScopeExit / [&]
						{
							CFRelease(pTrustSettings);
						}
					;

					if (CFArrayGetCount(pTrustSettings) == 0)
						return kSecTrustSettingsResultTrustRoot;

					auto fIsSSLPolicy = [](SecPolicyRef _pPolicy) -> bool
						{
							if (!_pPolicy)
								return false;

							auto pPolicyDictionary = SecPolicyCopyProperties(_pPolicy);
							if (!pPolicyDictionary)
								return false;

							auto Cleanup = g_OnScopeExit / [&]
								{
									CFRelease(pPolicyDictionary);
								}
							;

							CFTypeRef pValue = nullptr;

							if (CFDictionaryGetValueIfPresent(pPolicyDictionary, kSecPolicyOid, &pValue))
								return CFEqual(pValue, kSecPolicyAppleSSL);

							return false;
						}
					;

					for (umint i = 0; i < CFArrayGetCount(pTrustSettings); ++i)
					{
						CFDictionaryRef pTrustDictionary = reinterpret_cast<CFDictionaryRef>(const_cast<void*>(CFArrayGetValueAtIndex(pTrustSettings, i)));

						if (SecPolicyRef pPolicy = nullptr; CFDictionaryGetValueIfPresent(pTrustDictionary, kSecTrustSettingsPolicy, (void const **)&pPolicy))
						{
							if (!fIsSSLPolicy(pPolicy))
								continue;
						}

						if (CFStringRef pHostname = nullptr; CFDictionaryGetValueIfPresent(pTrustDictionary, kSecTrustSettingsPolicyString, (void const **)&pHostname))
							continue;

						if (CFNumberRef pTrustResult = nullptr; CFDictionaryGetValueIfPresent(pTrustDictionary, kSecTrustSettingsResult, (void const **)&pTrustResult))
						{
							SInt32 Result = 0;
							if (!CFNumberGetValue(pTrustResult, kCFNumberSInt32Type, &Result))
								return kSecTrustSettingsResultInvalid;

							if (Result == kSecTrustSettingsResultTrustRoot || Result == kSecTrustSettingsResultTrustAsRoot || Result == kSecTrustSettingsResultDeny)
								return (SecTrustSettingsResult)Result;
						}
						else
							return kSecTrustSettingsResultTrustRoot;
					}

					return kSecTrustSettingsResultUnspecified;
				}
			;

			auto fAddTrustStore = [&](CFArrayRef pCerts, SecTrustSettingsDomain _Domain)
				{
					for (umint i = 0; i < CFArrayGetCount(pCerts); ++i)
					{
						SecCertificateRef pCertRef = reinterpret_cast<SecCertificateRef>(const_cast<void*>(CFArrayGetValueAtIndex(pCerts, i)));
						X509 *pCertificate;
						if (CSystem::ms_PlatformVersion >= 10'06'00)
						{
							CFDataRef DERCert = SecCertificateCopyData(pCertRef);
							if (!DERCert)
								continue;

							{
								unsigned const char *pDERCert = CFDataGetBytePtr(DERCert);
								umint DataLength = CFDataGetLength(DERCert);
								pCertificate = d2i_X509(nullptr, &pDERCert, DataLength);
							}
							CFRelease(DERCert);
						}
						else
						{
							DMibDeprecatedSuppressStart;
							// This code is not tested. Is it in the right format?
							CSSM_DATA certCSSMData;
							if (SecCertificateGetData(pCertRef, &certCSSMData) != 0 || certCSSMData.Length == 0)
								continue;

							{
								unsigned const char *pDERCert = certCSSMData.Data;
								umint DataLength = certCSSMData.Length;
								pCertificate = d2i_X509(nullptr, &pDERCert, DataLength);
							}
							DMibDeprecatedSuppressStop;
						}

						if (!pCertificate)
							continue;

						auto Cleanup = g_OnScopeExit / [&]
							{
								X509_free(pCertificate);
							}
						;

						NContainer::CByteVector Certificate;

						try
						{
							Certificate = fg_ConvertX509ToBinary(pCertificate);
						}
						catch (...)
						{
							continue;
						}

						SecTrustSettingsResult TrustResult = kSecTrustSettingsResultInvalid;

						if (_Domain == kSecTrustSettingsDomainSystem)
							TrustResult = kSecTrustSettingsResultTrustRoot;
						else
						{
							if (CSystem::ms_PlatformVersion >= 10'07'00)
								TrustResult = fCheckTrust10_7(pCertRef);
						}

						try
						{
							switch (TrustResult)
							{
							case kSecTrustSettingsResultTrustRoot:
								{
									if (CCertificate::fs_IsRoot(Certificate))
										Trusted[Certificate];
								}
								break;
							case kSecTrustSettingsResultTrustAsRoot:
								{
									if (!CCertificate::fs_IsRoot(Certificate))
										Trusted[Certificate];
								}
								break;
							case kSecTrustSettingsResultDeny:
								Untrusted[Certificate];
								break;
							case kSecTrustSettingsResultUnspecified:
							case kSecTrustSettingsResultInvalid:
								break;
							}
						}
						catch (CExceptionCryptography const &)
						{
						}
					}
					CFRelease(pCerts);
				}
			;

			if (CSystem::ms_PlatformVersion >= 10'05'00)
			{
				CFArrayRef pCerts;
				if (SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainUser, &pCerts) == 0)
					fAddTrustStore(pCerts, kSecTrustSettingsDomainUser);
				if (SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainAdmin, &pCerts) == 0)
					fAddTrustStore(pCerts, kSecTrustSettingsDomainAdmin);
				if (SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainSystem, &pCerts) == 0)
					fAddTrustStore(pCerts, kSecTrustSettingsDomainSystem);
			}
			else
			{
				CFArrayRef pCerts;
				if (SecTrustCopyAnchorCertificates(&pCerts) == 0)
					fAddTrustStore(pCerts, kSecTrustSettingsDomainSystem);
			}

			for (auto &Certificate : Trusted)
			{
				if (Untrusted.f_FindEqual(Certificate))
					continue;

				auto *pCertificate = fg_LoadCertificate(Certificate);
				auto Cleanup = g_OnScopeExit / [&]
					{
						X509_free(pCertificate);
					}
				;

				if (fg_GetX509ExpireTime(pCertificate) > Now)
					X509_STORE_add_cert(pStore, pCertificate);
			}

			return pStore;
		}

#else

		X509_STORE *fg_ExtractSystemCertificates()
		{
			auto pStore = X509_STORE_new();

			auto fLoadCerts = [&](NStr::CStr const  &_File) -> bool
				{
					try
					{
						if (!NFile::CFile::fs_FileExists(_File, NFile::EFileAttrib_File))
						{
							DMibLog(Debug, "Unable to find: {}", _File);
							return false;
						}
					}
					catch ([[maybe_unused]] NFile::CExceptionFile const &_Exception)
					{
						DMibLog(Debug, "Exception trying to check file exists on: {}. The error reported was {}", _File, _Exception.f_GetErrorStr());
						return false;
					}

					int Ret = X509_STORE_load_locations(pStore, _File.f_GetStr(), nullptr);
					if (Ret == 0)
					{
						DMibLog(Debug, "Failed to load SSL verify location: {}. The error reported was {}", _File, fg_GetErrors());
						return false;
					}
					else
					{
						DMibLog(Debug, "Successfully added {} to SSL verify locations", _File);
						return true;
					}
				}
			;

			if (auto CertFile = fg_GetSys()->f_GetEnvironmentVariable("SSL_CERT_FILE"))
				fLoadCerts(CertFile);
			else
			{
				for
					(
						auto &CertFile :
						{
							"/etc/ssl/certs/ca-certificates.crt" // Debian/Ubuntu/Gentoo etc.
							, "/etc/pki/tls/certs/ca-bundle.crt" // Fedora/RHEL 6
							, "/etc/ssl/ca-bundle.pem" // OpenSUSE
							, "/etc/pki/tls/cacert.pem" // OpenELEC
							, "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem" // CentOS/RHEL 7
							, "/etc/ssl/cert.pem" // Alpine Linux
						}
					)
				{
					if (fLoadCerts(CertFile))
						break;
				}
			}

			NContainer::TCVector<NStr::CStr> CertDirectories =
				{
					"/etc/ssl/certs", // SLES10/SLES11
					"/etc/pki/tls/certs", // Fedora/RHEL
					"/system/etc/security/cacerts", // Android
				}
			;

			if (auto CertDir = fg_GetSys()->f_GetEnvironmentVariable("SSL_CERT_DIR"))
				CertDirectories = CertDir.f_Split<true>(":");

			for (auto &Directory : CertDirectories)
			{
				for (auto &File : NFile::CFile::fs_FindFiles(Directory + "/*"))
					fLoadCerts(File);
			}

			return pStore;
		}
#endif
	}

	void CCertificate::fs_GetSystemCertificates(X509_STORE *_pCertificateStoreStore)
	{
		auto &Globals = *g_CertificateGlobals;

		if (!Globals.m_pSystemCertStore)
		{
			DMibLock(Globals.m_SystemCertStoreLock);
			if (!Globals.m_pSystemCertStore)
				Globals.m_pSystemCertStore = fg_ExtractSystemCertificates();
		}

		STACK_OF(X509_OBJECT) *certs = X509_STORE_get0_objects(Globals.m_pSystemCertStore);
		/* Look for exact match */
		for (umint i = 0; i < sk_X509_OBJECT_num(certs); i++)
		{
			X509_OBJECT const *pObject = sk_X509_OBJECT_value(certs, i);
			if (X509_OBJECT_get_type(pObject) != X509_LU_X509)
				continue;
			X509_STORE_add_cert(_pCertificateStoreStore, X509_OBJECT_get0_X509(pObject));
		}
	}
}
