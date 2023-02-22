#include "Malterlib_Cryptography_Certificate.h"
#include "Malterlib_Cryptography_Certificate_Internal.h"

#include <Mib/Cryptography/BoringSSL>

namespace NMib::NCryptography
{
	using namespace NBoringSSL;

	namespace
	{
		X509_EXTENSION *fg_CreateExtension(X509V3_CTX &_Context, int _nID, CCertificateExtension _Extension)
		{
			X509_EXTENSION *pExtension = nullptr;

			int Critical = _Extension.m_bCritical;
			ERR_clear_error();
			pExtension = X509V3_EXT_conf_nid(nullptr, &_Context, _nID, _Extension.m_Value.f_GetStrUniqueWritable());
			if (pExtension)
			{
				X509_EXTENSION_set_critical(pExtension, Critical);
				return pExtension;
			}

			ASN1_UTF8STRING *pValue = nullptr;

			ERR_clear_error();
			pValue = ASN1_UTF8STRING_new();
			if (!pValue)
				DMibErrorCryptography(fg_GetExceptionStr("Failed to create ASN1 value"));

			auto Cleanup = g_OnScopeExit / [&]
				{
					pValue->length = 0;
					pValue->data = nullptr;
					ASN1_UTF8STRING_free(pValue);
				}
			;
			pValue->length = _Extension.m_Value.f_GetLen();
			pValue->data = (unsigned char *)_Extension.m_Value.f_GetStrUniqueWritable();
			ERR_clear_error();
			pExtension = X509_EXTENSION_create_by_NID(&pExtension, _nID, Critical, pValue);
			if (!pExtension)
				DMibErrorCryptography(fg_GetExceptionStr("Failed to create extension"));

			return pExtension;
		}

		void fg_AddExtension(X509V3_CTX &_Context, X509 *_pCert, int _nID, CCertificateExtension _Extension)
		{
			X509_EXTENSION *pExtension = nullptr;
			pExtension = fg_CreateExtension(_Context, _nID, _Extension);

			auto Cleanup1 = g_OnScopeExit / [&]
				{
					X509_EXTENSION_free(pExtension);
				}
			;

			ERR_clear_error();
			if (!X509_add_ext(_pCert,pExtension,-1))
				DMibErrorCryptography(fg_GetExceptionStr("Error adding x509 extension"));
		}

		void fg_AddExtension(X509V3_CTX &_Context, X509_EXTENSIONS *&_pExtensions, int _nID, CCertificateExtension _Extension)
		{
			X509_EXTENSION *pExtension = fg_CreateExtension(_Context, _nID, _Extension);
			auto Cleanup = g_OnScopeExit / [&]
				{
					X509_EXTENSION_free(pExtension);
				}
			;

			ERR_clear_error();
			X509v3_add_ext(&_pExtensions, pExtension, -1);
		}

		template <typename tf_CObject>
		void fg_AddHostnames(X509V3_CTX &_Context, tf_CObject *&_pObject, NContainer::TCVector<NStr::CStr> const &_Hostnames)
		{
			NContainer::TCVector<NStr::CStr> SortedHosts = CCertificate::fs_GetSortedHostnames(_Hostnames);

			NStr::CStr Output;
			for (auto Iter = SortedHosts.f_GetIterator(); Iter; ++Iter)
			{
				if (Output.f_IsEmpty())
					Output = NStr::CStr::CFormat("DNS:{}") << (*Iter);
				else
					Output += NStr::CStr::CFormat(",DNS:{}") << (*Iter);
			}

			CCertificateExtension Extension;
			Extension.m_Value = Output;
			fg_AddExtension(_Context, _pObject, NID_subject_alt_name, Extension);
		}

		template <typename tf_CObject>
		void fg_AddExtensions(X509V3_CTX &_Context, tf_CObject *&_pObject, NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> const &_Extensions)
		{
			for (auto iExtension = _Extensions.f_GetIterator(); iExtension; ++iExtension)
			{
				ERR_clear_error();
				int NumericID = OBJ_txt2nid(iExtension.f_GetKey());

				if (NumericID == NID_undef)
					DMibErrorCryptography(fg_GetExceptionStr(fg_Format("Unknown extension '{}'", iExtension.f_GetKey())));

				for (auto &Extension : *iExtension)
					fg_AddExtension(_Context, _pObject, NumericID, Extension);
			}
		}
	}

	static void fg_GenerateSubject(X509_NAME *_pName, CCertificateOptions const &_Options)
	{
		ERR_clear_error();
		if (!X509_NAME_add_entry_by_txt(_pName, "CN", MBSTRING_UTF8, (const unsigned char*)_Options.m_CommonName.f_GetStr(), -1, -1, 0))
			DMibErrorCryptography(fg_GetExceptionStr("Error adding CN entry"));

		for (auto &Value : _Options.m_RelativeDistinguishedNames)
		{
			auto &Subject = _Options.m_RelativeDistinguishedNames.fs_GetKey(Value);
			ERR_clear_error();
			if (!X509_NAME_add_entry_by_txt(_pName, Subject, MBSTRING_UTF8, (const unsigned char*)Value.f_GetStr(), -1, -1, 0))
				DMibErrorCryptography(fg_GetExceptionStr(fg_Format("Error adding {} entry", Subject)));
		}
	}

	// openssl genrsa -des3 -out client.key 4096
	// openssl req -new -key client.key -out client.csr
	void CCertificate::fs_GenerateClientCertificateRequest
		(
			CCertificateOptions const &_Options
			, NContainer::CByteVector &o_CertRequestData
			, NContainer::CSecureByteVector &o_KeyData
			, EDigestType _Digest
		)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					o_CertRequestData.f_Clear();

					bool bGenerateNewKey = o_KeyData.f_IsEmpty();

					EVP_PKEY *pKey;
					if (bGenerateNewKey)
					{
						ERR_clear_error();
						pKey = EVP_PKEY_new();
						if (!pKey)
							DMibErrorCryptography(fg_GetExceptionStr("Error creating key"));
					}
					else
						pKey = fg_LoadPrivateKey(o_KeyData);

					auto Cleanup0 = g_OnScopeExit / [&] ()
						{
							EVP_PKEY_free(pKey);
						}
					;

					ERR_clear_error();
					X509_REQ *pCertificateRequest = X509_REQ_new();
					if (!pCertificateRequest)
						DMibErrorCryptography(fg_GetExceptionStr("Error creating certificate request"));
					auto Cleanup1 = g_OnScopeExit / [&] ()
						{
							X509_REQ_free(pCertificateRequest);
						}
					;

					if (bGenerateNewKey)
						fg_GenerateKey(pKey, _Options);

					fg_GenerateSubject(X509_REQ_get_subject_name(pCertificateRequest), _Options);

					X509_EXTENSIONS *pExtensions = nullptr;

					auto Cleanup2 = g_OnScopeExit / [&]
						{
							if (pExtensions)
								sk_X509_EXTENSION_pop_free(pExtensions, X509_EXTENSION_free);
						}
					;

					{
						X509V3_CTX Context;
						X509V3_set_ctx_nodb(&Context);
						X509V3_set_ctx(&Context, nullptr, nullptr, pCertificateRequest, nullptr, 0);
						if (!_Options.m_Hostnames.f_IsEmpty())
							fg_AddHostnames(Context, pExtensions, _Options.m_Hostnames);

						if (!_Options.m_Extensions.f_IsEmpty())
							fg_AddExtensions(Context, pExtensions, _Options.m_Extensions);
					}

					if (pExtensions)
					{
						if (!X509_REQ_add_extensions(pCertificateRequest, pExtensions))
							DMibErrorCryptography(fg_GetExceptionStr("Error adding x509 req extensions"));
					}

					ERR_clear_error();
					if (!X509_REQ_set_pubkey(pCertificateRequest, pKey))
						DMibErrorCryptography(fg_GetExceptionStr("Error setting request public key"));

					ERR_clear_error();
					if (!X509_REQ_sign(pCertificateRequest, pKey, fg_GetDigest(_Digest, pKey)))
						DMibErrorCryptography(fg_GetExceptionStr("Error signing request"));

					o_CertRequestData = fg_ConvertX509RequestToBinary(pCertificateRequest);
					if (bGenerateNewKey)
						o_KeyData = fg_ConvertKeyToBinary(pKey);
				}
			)
		;
	}

	// openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out client.crt

	void CCertificate::fs_VerifyCertificateRequestSameKeyAsCertificate(NContainer::CByteVector const &_CertRequestData, NContainer::CByteVector const &_CertData)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					X509_REQ *pCertificateRequest = fg_LoadCertificateRequest(_CertRequestData);
					auto Cleanup0 = g_OnScopeExit / [&] ()
						{
							X509_REQ_free(pCertificateRequest);
						}
					;

					X509 *pCertificate = fg_LoadCertificate(_CertData);
					auto Cleanup3 = g_OnScopeExit / [&] ()
						{
							X509_free(pCertificate);
						}
					;

					// Get public key from certificate
					ERR_clear_error();
					auto pPublicKey = X509_get_pubkey(pCertificate);
					if (!pPublicKey)
						DMibErrorCryptography(fg_GetExceptionStr("Found no public key in certificate"));
					auto Cleanup = g_OnScopeExit / [&]
						{
							EVP_PKEY_free(pPublicKey);
						}
					;

					// Verify with certificate request
					ERR_clear_error();
					int VerifyResult = X509_REQ_verify(pCertificateRequest, pPublicKey);
					if (VerifyResult < 0)
						DMibErrorCryptography(fg_GetExceptionStr("Signature verification error"));
					else if (VerifyResult == 0)
						DMibErrorCryptography("Certificate request signature mismatch");
				}
			)
		;
	}

	void CCertificate::fs_SignClientCertificate
		(
			NContainer::CByteVector const &_CACertificate
			, NContainer::CSecureByteVector const &_CAKey
			, NContainer::CByteVector const &_CertRequestData
			, NContainer::CByteVector &o_SignedCertificateData
			, CCertificateSignOptions const &_SignOptions
		)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					o_SignedCertificateData.f_Clear();

					X509_REQ *pCertificateRequest = fg_LoadCertificateRequest(_CertRequestData);
					auto Cleanup0 = g_OnScopeExit / [&] ()
						{
							X509_REQ_free(pCertificateRequest);
						}
					;

					EVP_PKEY *pCAKey = fg_LoadPrivateKey(_CAKey);
					auto Cleanup2 = g_OnScopeExit / [&] ()
						{
							EVP_PKEY_free(pCAKey);
						}
					;

					X509 *pCACertificate = fg_LoadCertificate(_CACertificate);
					auto Cleanup3 = g_OnScopeExit / [&] ()
						{
							X509_free(pCACertificate);
						}
					;

					ERR_clear_error();
					X509 *pCertificate = X509_new();
					if (!pCertificate)
						DMibErrorCryptography(fg_GetExceptionStr("Error creating certificate"));
					auto Cleanup1 = g_OnScopeExit / [&] ()
						{
							X509_free(pCertificate);
						}
					;

					{
						ERR_clear_error();
						EVP_PKEY *pPublicKey = X509_REQ_get_pubkey(pCertificateRequest);
						if (!pPublicKey)
							DMibErrorCryptography(fg_GetExceptionStr("The certificate request does not contain a public key"));

						auto Cleanup = g_OnScopeExit / [&] ()
							{
								EVP_PKEY_free(pPublicKey);
							}
						;
						ERR_clear_error();
						int VerifyResult = X509_REQ_verify(pCertificateRequest, pPublicKey);
						if (VerifyResult < 0)
							DMibErrorCryptography(fg_GetExceptionStr("Signature verification error"));
						else if (VerifyResult == 0)
							DMibErrorCryptography("Certificate request signature mismatch");
					}

					ERR_clear_error();
					if (!X509_set_version(pCertificate, 2))
						DMibErrorCryptography(fg_GetExceptionStr("Error setting x509 version"));

					ERR_clear_error();
					if (!ASN1_INTEGER_set(X509_get_serialNumber(pCertificate), _SignOptions.m_Serial))
						DMibErrorCryptography(fg_GetExceptionStr("Error setting x509 serial"));

					ERR_clear_error();
					if (!X509_gmtime_adj(X509_get_notBefore(pCertificate), -60)) // 60 seconds in the past to account for system clock adjustments
						DMibErrorCryptography(fg_GetExceptionStr("Error setting x509 not before"));

					ERR_clear_error();
					if (!X509_time_adj_ex(X509_get_notAfter(pCertificate), _SignOptions.m_Days, 0, nullptr))
						DMibErrorCryptography(fg_GetExceptionStr("Error setting x509 not after"));

					ERR_clear_error();
					if (!X509_set_issuer_name(pCertificate, X509_get_subject_name(pCACertificate)))
						DMibErrorCryptography(fg_GetExceptionStr("Error setting x509 issuer"));


					ERR_clear_error();
					if (!X509_set_subject_name(pCertificate, X509_REQ_get_subject_name(pCertificateRequest)))
						DMibErrorCryptography(fg_GetExceptionStr("Error setting x509 subject name"));

					{
						ERR_clear_error();
						auto pPublicKey = X509_REQ_get_pubkey(pCertificateRequest);
						if (!pPublicKey)
							DMibErrorCryptography(fg_GetExceptionStr("Found no public key in certificate"));
						auto Cleanup = g_OnScopeExit / [&]
							{
								EVP_PKEY_free(pPublicKey);
							}
						;

						ERR_clear_error();
						if (!X509_set_pubkey(pCertificate, pPublicKey))
							DMibErrorCryptography(fg_GetExceptionStr("Error setting x509 public key"));
					}

					{
						ERR_clear_error();
						auto pCAPublicKey = X509_get_pubkey(pCACertificate);
						if (!pCAPublicKey)
							DMibErrorCryptography(fg_GetExceptionStr("Error getting CA certificate public key"));
						auto Cleanup = g_OnScopeExit / [&]
							{
								EVP_PKEY_free(pCAPublicKey);
							}
						;

						EVP_PKEY_copy_parameters(pCAPublicKey, pCAKey);
					}

					{
						X509_EXTENSIONS *pExtensions = X509_REQ_get_extensions(pCertificateRequest);

						auto Cleanup = g_OnScopeExit / [&]
							{
								if (pExtensions)
									sk_X509_EXTENSION_pop_free(pExtensions, X509_EXTENSION_free);
							}
						;

						if (pExtensions)
						{
							ERR_clear_error();
							int nExtensions = X509v3_get_ext_count(pExtensions);
							if (nExtensions < 0)
								DMibErrorCryptography(fg_GetExceptionStr("Failed to get extension count from certificate request"));

							for (int iExtension = 0; iExtension < nExtensions; ++iExtension)
							{
								ERR_clear_error();
								auto *pExtension = X509v3_get_ext(pExtensions, iExtension);
								if (!pExtension)
									DMibErrorCryptography(fg_GetExceptionStr("Failed to get extension from certificate request"));
								ERR_clear_error();
								if (!X509_add_ext(pCertificate, pExtension, -1))
									DMibErrorCryptography(fg_GetExceptionStr("Failed to add extension to certificate"));
							}
						}
					}

					if (!_SignOptions.m_Extensions.f_IsEmpty())
					{
						X509V3_CTX Context;
						X509V3_set_ctx_nodb(&Context);
						X509V3_set_ctx(&Context, pCACertificate, pCertificate, nullptr, nullptr, 0);
						fg_AddExtensions(Context, pCertificate, _SignOptions.m_Extensions);
					}

					ERR_clear_error();
					if (!X509_check_private_key(pCACertificate, pCAKey))
						DMibErrorCryptography(fg_GetExceptionStr("CA certificate and CA private key do not match"));

					ERR_clear_error();
					if (!X509_sign(pCertificate, pCAKey, fg_GetDigest(_SignOptions.m_Digest, pCAKey)))
						DMibErrorCryptography(fg_GetExceptionStr("Error signing certificate request"));

					o_SignedCertificateData = fg_ConvertX509ToBinary(pCertificate);
				}
			)
		;
	}

	// openssl genrsa -des3 -out ca.key 4096
	// openssl req -new -x509 -days 365 -key ca.key -out ca.crt

	void CCertificate::fs_GenerateSelfSignedCertAndKey
		(
			CCertificateOptions const &_Options
			, NContainer::CByteVector &o_CertData
			, NContainer::CSecureByteVector &o_KeyData
			, CCertificateSignOptions const &_SignOptions
		)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					o_CertData.f_Clear();
					o_KeyData.f_Clear();

					ERR_clear_error();
					X509 *pCertificate = X509_new();
					if (!pCertificate)
						DMibErrorCryptography(fg_GetExceptionStr("Error creating certificate"));
					auto Cleanup0 = g_OnScopeExit / [&] ()
						{
							X509_free(pCertificate);
						}
					;
					ERR_clear_error();
					EVP_PKEY* pKey = EVP_PKEY_new();
					if (!pKey)
						DMibErrorCryptography(fg_GetExceptionStr("Error creating key"));
					auto Cleanup1 = g_OnScopeExit / [&] ()
						{
							EVP_PKEY_free(pKey);
						}
					;

					fg_GenerateKey(pKey, _Options);

					ERR_clear_error();
					if (!X509_set_version(pCertificate, 2))
						DMibErrorCryptography(fg_GetExceptionStr("Error setting x509 version"));

					ERR_clear_error();
					if (!ASN1_INTEGER_set(X509_get_serialNumber(pCertificate), _SignOptions.m_Serial))
						DMibErrorCryptography(fg_GetExceptionStr("Error setting x509 serial"));

					ERR_clear_error();
					if (!X509_gmtime_adj(X509_get_notBefore(pCertificate), -60)) // 60 seconds in the past to account for system clock adjustments
						DMibErrorCryptography(fg_GetExceptionStr("Error setting x509 not before"));

					ERR_clear_error();
					if (!X509_time_adj_ex(X509_get_notAfter(pCertificate), _SignOptions.m_Days, 0, nullptr))
						DMibErrorCryptography(fg_GetExceptionStr("Error setting x509 not after"));

					ERR_clear_error();
					if (!X509_set_pubkey(pCertificate, pKey))
						DMibErrorCryptography(fg_GetExceptionStr("Error setting x509 public key"));

					fg_GenerateSubject(X509_get_subject_name(pCertificate), _Options);

					// Self signed.
					ERR_clear_error();
					if (!X509_set_issuer_name(pCertificate, X509_get_subject_name(pCertificate)))
						DMibErrorCryptography(fg_GetExceptionStr("Error setting x509 issuer"));

					// Set the subjectAltName
					{
						X509V3_CTX Context;
						X509V3_set_ctx_nodb(&Context);
						X509V3_set_ctx(&Context, pCertificate, pCertificate, nullptr, nullptr, 0);

						if (!_Options.m_Hostnames.f_IsEmpty())
							fg_AddHostnames(Context, pCertificate, _Options.m_Hostnames);

						if (!_Options.m_Extensions.f_IsEmpty())
							fg_AddExtensions(Context, pCertificate, _Options.m_Extensions);

						if (!_SignOptions.m_Extensions.f_IsEmpty())
							fg_AddExtensions(Context, pCertificate, _SignOptions.m_Extensions);
					}

					ERR_clear_error();
					if (!X509_sign(pCertificate, pKey, fg_GetDigest(_SignOptions.m_Digest, pKey)))
						DMibErrorCryptography(fg_GetExceptionStr("Error signing selfsigned certificate"));

					o_CertData = fg_ConvertX509ToBinary(pCertificate);
					o_KeyData = fg_ConvertKeyToBinary(pKey);
				}
			)
		;
	}

	NContainer::CByteVector CCertificate::fs_ConvertToDer_CertificateSigningRequest(NContainer::CByteVector const &_Pem)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					X509_REQ *pCertificateRequest = fg_LoadCertificateRequest(_Pem);
					auto Cleanup0 = g_OnScopeExit / [&] ()
						{
							X509_REQ_free(pCertificateRequest);
						}
					;

					ERR_clear_error();
					BIO* pMemoryBio = BIO_new(BIO_s_mem());
					if (!pMemoryBio)
						DMibErrorCryptography(fg_GetExceptionStr("Error creating BIO"));
					auto Cleanup = g_OnScopeExit / [&]
						{
							BIO_free(pMemoryBio);
						}
					;

					ERR_clear_error();
					if (!i2d_X509_REQ_bio(pMemoryBio, pCertificateRequest))
						DMibErrorCryptography(fg_GetExceptionStr("Error writing certificate signing request to BIO"));

					NContainer::CByteVector Return;
					Return.f_SetLen(pMemoryBio->num_write);
					ERR_clear_error();
					if (!BIO_read(pMemoryBio, Return.f_GetArray(), Return.f_GetLen()))
						DMibErrorCryptography(fg_GetExceptionStr("Error reading certificate signing request from BIO"));
					return Return;

				}
			)
		;
	}

	NContainer::CByteVector CCertificate::fs_ConvertToDer_Certificate(NContainer::CByteVector const &_Pem)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					X509 *pCertificate = fg_LoadCertificate(_Pem);
					auto Cleanup0 = g_OnScopeExit / [&] ()
						{
							X509_free(pCertificate);
						}
					;

					ERR_clear_error();
					BIO* pMemoryBio = BIO_new(BIO_s_mem());
					if (!pMemoryBio)
						DMibErrorCryptography(fg_GetExceptionStr("Error creating BIO"));
					auto Cleanup = g_OnScopeExit / [&]
						{
							BIO_free(pMemoryBio);
						}
					;

					ERR_clear_error();
					if (!i2d_X509_bio(pMemoryBio, pCertificate))
						DMibErrorCryptography(fg_GetExceptionStr("Error writing certificate signing request to BIO"));

					NContainer::CByteVector Return;
					Return.f_SetLen(pMemoryBio->num_write);
					ERR_clear_error();
					if (!BIO_read(pMemoryBio, Return.f_GetArray(), Return.f_GetLen()))
						DMibErrorCryptography(fg_GetExceptionStr("Error reading certificate signing request from BIO"));
					return Return;

				}
			)
		;
	}
}
