#include "Malterlib_Cryptography_Certificate.h"

#include <Mib/Cryptography/BoringSSL>

#if defined(DPlatformFamily_OSX)
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

		NStorage::TCAggregate<CCertificateGlobals, 129> g_CertificateGlobals = {DAggregateInit};
	}

	namespace
	{
		X509_STORE *fg_ExtractSystemCertificates()
		{
			auto pStore = X509_STORE_new();

			#if defined(DPlatformFamily_Windows)

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
						auto Cleanup0 = g_OnScopeExit > [&]
							{
								X509_free(pCertificate);
							}
						;

						X509_STORE_add_cert(pStore, pCertificate);
					}

					CertCloseStore(hStore, 0);
				};

				fLoadFromStore(L"ROOT");
				fLoadFromStore(L"CA");

			#elif defined(DPlatformFamily_OSX)

				auto fAddTrustStore = [&](CFArrayRef pCerts)
					{
						for (int i = 0; i < CFArrayGetCount(pCerts); ++i)
						{
							SecCertificateRef CertRef = reinterpret_cast<SecCertificateRef>(const_cast<void*>(CFArrayGetValueAtIndex(pCerts, i)));

							X509 *pCertificate;
			#if DPlatformVersionMax >= 1060
							if (CSystem::ms_PlatformVersion >= 10'06'00)
							{
								CFDataRef DERCert = SecCertificateCopyData(CertRef);
								if (!DERCert)
									continue;

								unsigned const char *pDERCert = CFDataGetBytePtr(DERCert);
								mint DataLength = CFDataGetLength(DERCert);
								pCertificate = d2i_X509(nullptr, &pDERCert, DataLength);
								CFRelease(DERCert);
							}
							else
			#endif
							{
								DMibDeprecatedSupressStart;
								// This code is not tested. Is it in the right format?
								CSSM_DATA certCSSMData;
								if (SecCertificateGetData(CertRef, &certCSSMData) != 0 || certCSSMData.Length == 0)
									continue;
								unsigned const char *pDERCert = certCSSMData.Data;
								mint DataLength = certCSSMData.Length;
								pCertificate = d2i_X509(nullptr, &pDERCert, DataLength);
								DMibDeprecatedSupressStop;
							}

							if (!pCertificate)
								continue;

							auto Cleanup = g_OnScopeExit > [&]
								{
									X509_free(pCertificate);
								}
							;

							X509_STORE_add_cert(pStore, pCertificate);
						}
						CFRelease(pCerts);
					}
				;

				if (CSystem::ms_PlatformVersion >= 10'05'00)
				{
					CFArrayRef pCerts;
					if (SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainSystem, &pCerts) == 0)
						fAddTrustStore(pCerts);
					if (SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainAdmin, &pCerts) == 0)
						fAddTrustStore(pCerts);
					if (SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainUser, &pCerts) == 0)
						fAddTrustStore(pCerts);
				}
				else
				{
					CFArrayRef pCerts;
					if (SecTrustCopyAnchorCertificates(&pCerts) == 0)
						fAddTrustStore(pCerts);
				}

			#else

				auto fLoadCerts =
					[&](NStr::CStr const  &_File) -> bool
					{
						try
						{
							if (!NFile::CFile::fs_FileExists(_File, NFile::EFileAttrib_File))
							{
								DMibLog(Debug, "Unable to find: {}", _File);
								return false;
							}
						}
						catch (NFile::CExceptionFile const  &_Exception)
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

				if (fLoadCerts("/etc/ssl/certs/ca-certificates.crt"))
					;
				else if (fLoadCerts("/etc/ssl/certs/ca-bundle.crt"))
					;

			#endif

			return pStore;
		}
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
		for (mint i = 0; i < sk_X509_OBJECT_num(certs); i++)
		{
			X509_OBJECT const *pObject = sk_X509_OBJECT_value(certs, i);
			if (pObject->type != X509_LU_X509)
				continue;
			X509_STORE_add_cert(_pCertificateStoreStore, pObject->data.x509);
		}
	}
}
