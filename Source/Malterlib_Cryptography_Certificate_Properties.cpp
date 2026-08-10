// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Cryptography_Certificate.h"
#include "Malterlib_Cryptography_Certificate_Internal.h"

#include <Mib/Cryptography/BoringSSL>

namespace NMib::NCryptography
{
	using namespace NBoringSSL;

	namespace
	{
		int fg_GetDigestNIDFromAlgorithm(X509_ALGOR const *_pAlgorithm)
		{
			if (!_pAlgorithm)
				return NID_undef;

			ASN1_OBJECT const *pObject = nullptr;
			X509_ALGOR_get0(&pObject, nullptr, nullptr, _pAlgorithm);
			if (!pObject)
				return NID_undef;

			return OBJ_obj2nid(pObject);
		}

		int fg_GetTLSServerEndPointDigestNIDFromRSAPSS(X509 const *_pCertificate)
		{
			X509_ALGOR const *pSignatureAlgorithm = nullptr;
			X509_get0_signature(nullptr, &pSignatureAlgorithm, _pCertificate);
			if (!pSignatureAlgorithm)
				DMibErrorCryptography("Failed to read certificate signature algorithm");

			int ParameterType = V_ASN1_UNDEF;
			void const *pParameterValue = nullptr;
			X509_ALGOR_get0(nullptr, &ParameterType, &pParameterValue, pSignatureAlgorithm);
			if (ParameterType == V_ASN1_UNDEF)
				return NID_sha1;
			if (ParameterType != V_ASN1_SEQUENCE || !pParameterValue)
				DMibErrorCryptography("Invalid RSASSA-PSS certificate signature parameters");

			ASN1_STRING const *pParameterString = (ASN1_STRING const *)pParameterValue;
			uint8 const *pParameterData = ASN1_STRING_get0_data(pParameterString);
			long ParameterLength = ASN1_STRING_length(pParameterString);
			RSA_PSS_PARAMS *pPSSParameters = d2i_RSA_PSS_PARAMS(nullptr, &pParameterData, ParameterLength);
			if (!pPSSParameters)
				DMibErrorCryptography(fg_GetExceptionStr("Failed to parse RSASSA-PSS certificate signature parameters"));
			auto Cleanup = g_OnScopeExit / [&]
				{
					RSA_PSS_PARAMS_free(pPSSParameters);
				}
			;

			if (pParameterData != ASN1_STRING_get0_data(pParameterString) + ParameterLength)
				DMibErrorCryptography("Trailing data in RSASSA-PSS certificate signature parameters");

			if (!pPSSParameters->hashAlgorithm)
				return NID_sha1;

			return fg_GetDigestNIDFromAlgorithm(pPSSParameters->hashAlgorithm);
		}

		EVP_MD const *fg_GetTLSServerEndPointDigestFromNID(int _DigestNID)
		{
			switch (_DigestNID)
			{
			case NID_sha224: return EVP_sha224();
			case NID_sha384: return EVP_sha384();
			case NID_sha512: return EVP_sha512();
			case NID_sha256:
			case NID_md5:
			case NID_sha1:
			default:
				return EVP_sha256();
			}
		}

		EVP_MD const *fg_GetTLSServerEndPointDigest(X509 const *_pCertificate)
		{
			int DigestNID = NID_undef;
			int SignatureNID = X509_get_signature_nid(_pCertificate);
			if (SignatureNID == NID_rsassaPss)
			{
				DigestNID = fg_GetTLSServerEndPointDigestNIDFromRSAPSS(_pCertificate);
				if (DigestNID == NID_undef)
					DMibErrorCryptography("Unsupported RSASSA-PSS certificate signature digest algorithm");
			}
			else if (!OBJ_find_sigid_algs(SignatureNID, &DigestNID, nullptr))
				DigestNID = NID_sha256;

			return fg_GetTLSServerEndPointDigestFromNID(DigestNID);
		}
	}

	NStr::CStr CCertificate::fs_GetCertificateDescription(NContainer::CByteVector const &_CertificateData)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					NStr::CStr CertificateDescription;
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_free(pCertificate);
						}
					;

					ERR_clear_error();
					BIO* pMemoryBio = BIO_new(BIO_s_mem());
					if (!pMemoryBio)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to create BIO"));
					auto Cleanup1 = g_OnScopeExit / [&]
						{
							BIO_free_all(pMemoryBio);
						}
					;

					BUF_MEM* pMemory = nullptr;

					unsigned long NameOptions = 0;
					unsigned long CertOptions = 0;

					ERR_clear_error();
					if (!X509_print_ex(pMemoryBio, pCertificate, NameOptions, CertOptions))
						DMibErrorCryptography(fg_GetExceptionStr("Failed to print x509 description"));

					(void)BIO_flush(pMemoryBio);
					BIO_get_mem_ptr(pMemoryBio, &pMemory);

					NContainer::CByteVector RawData;
					RawData.f_SetLen(pMemory->length);
					NMemory::fg_MemCopy(RawData.f_GetArray(), pMemory->data, pMemory->length - 1);

					RawData[RawData.f_GetLen() - 1] = '\0';
					return NStr::CStr((ch8 const *)RawData.f_GetArray());
				}
			)
		;
	}

	NStr::CStr CCertificate::fs_GetCertificateName(NContainer::CByteVector const &_CertificateData)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_free(pCertificate);
						}
					;

					char Buffer[256];
					ERR_clear_error();
					int nChars = X509_NAME_get_text_by_NID(X509_get_subject_name(pCertificate), NID_commonName, Buffer, 256);
					if (nChars < 0)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to read certificate name"));
					return NStr::CStr(Buffer, nChars);
				}
			)
		;
	}

	NStr::CStr CCertificate::fs_GetCertificateDistinguishedName_RFC2253(NContainer::CByteVector const &_CertificateData)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit / [&]
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
					int nChars = X509_NAME_print_ex(pMemoryBio, X509_get_subject_name(pCertificate), 0, XN_FLAG_RFC2253);
					if (nChars < 0)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to read certificate name"));

					auto nWritten = BIO_number_written(pMemoryBio);
					NStr::CStr Output;

					BIO_read(pMemoryBio, Output.f_GetStr(nWritten + 1), (int)nWritten);

					Output.f_SetAt(nWritten, 0);
					Output.f_SetStrLen(nWritten);
					return Output;
				}
			)
		;
	}

	NStr::CStr CCertificate::fs_GetCertificateFingerprint(NContainer::CByteVector const &_CertificateData)
	{
		NContainer::CByteVector Digest = fs_GetCertificateFingerprintData(_CertificateData);
		return NStr::CStr::fs_ToStr(NStr::CStrFormatBinaryWrapper(Digest.f_GetArray(), Digest.f_GetLen()));
	}

	NContainer::CByteVector CCertificate::fs_GetCertificateFingerprintData(NContainer::CByteVector const &_CertificateData, EDigestType _Digest)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_free(pCertificate);
						}
					;

					unsigned int DigestSize = 0;
					uint8 Digest[EVP_MAX_MD_SIZE];
					if (!X509_digest(pCertificate, fg_GetDigest(_Digest), Digest, &DigestSize))
						DMibErrorCryptography(fg_GetExceptionStr("Failed to calculate certificate digest"));

					return NContainer::CByteVector(Digest, DigestSize);
				}
			)
		;
	}

	NContainer::CByteVector CCertificate::fs_GetCertificateTLSServerEndPointData(NContainer::CByteVector const &_CertificateData)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_free(pCertificate);
						}
					;

					unsigned int DigestSize = 0;
					uint8 Digest[EVP_MAX_MD_SIZE];
					if (!X509_digest(pCertificate, fg_GetTLSServerEndPointDigest(pCertificate), Digest, &DigestSize))
						DMibErrorCryptography(fg_GetExceptionStr("Failed to calculate TLS server endpoint certificate digest"));

					return NContainer::CByteVector(Digest, DigestSize);
				}
			)
		;
	}

	bool CCertificate::fs_IsRoot(NContainer::CByteVector const &_CertificateData)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					NStr::CStr CertificateName;
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_free(pCertificate);
						}
					;
					auto pIssuer = X509_get_issuer_name(pCertificate);
					if (!pIssuer)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to read certificate issuer name"));

					auto pSubject = X509_get_subject_name(pCertificate);
					if (!pSubject)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to read certificate subject name"));

					return X509_NAME_cmp(pIssuer, pSubject) == 0;
				}
			)
		;
	}

	EDigestType CCertificate::fs_GetSignatureDigestType(NContainer::CByteVector const &_CertificateData)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_free(pCertificate);
						}
					;

					ASN1_BIT_STRING const *pSignature = nullptr;
					X509_ALGOR const *pSignatureAlgorithm = nullptr;
					X509_get0_signature(&pSignature, &pSignatureAlgorithm, pCertificate);
					if (!pSignatureAlgorithm)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to read certificate signature algorithm"));

					int DigestNID = fg_GetSignatureDigestNID(pSignatureAlgorithm);
					for (EDigestType Digest : {EDigestType_SHA512, EDigestType_SHA384, EDigestType_SHA256, EDigestType_SHA224, EDigestType_SHA1, EDigestType_MD5})
					{
						EVP_MD const *pDigest = fg_GetDigest(Digest);
						if (pDigest && EVP_MD_type(pDigest) == DigestNID)
							return Digest;
					}

					return EDigestType_None;
				}
			)
		;
	}

	NStr::CStr CCertificate::fs_GetIssuerName(NContainer::CByteVector const &_CertificateData)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					NStr::CStr CertificateName;
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_free(pCertificate);
						}
					;
					char Buffer[256];
					ERR_clear_error();
					int nChars = X509_NAME_get_text_by_NID(X509_get_issuer_name(pCertificate), NID_commonName, Buffer, 256);
					if (nChars < 0)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to read certificate issuer name"));
					return NStr::CStr(Buffer);
				}
			)
		;
	}

	NContainer::TCVector<NStr::CStr> CCertificate::fs_GetCertificateHostnames(NContainer::CByteVector const &_CertificateData, bool _bCheckCommonName)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					NContainer::TCVector<NStr::CStr> lHostnames;

					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_free(pCertificate);
						}
					;

					// First look at "subjectAltNames"
					int Index = -1;
					while(true)
					{
						GENERAL_NAMES* pSubjectAltNames = (GENERAL_NAMES*)X509_get_ext_d2i(pCertificate, NID_subject_alt_name, nullptr, &Index);
						if (!pSubjectAltNames)
							break;
						auto Cleanup = g_OnScopeExit / [&]
							{
								GENERAL_NAMES_free(pSubjectAltNames);
							}
						;
						umint nAltEntries = sk_GENERAL_NAME_num(pSubjectAltNames);

						for (umint iEntry = 0; iEntry < nAltEntries; ++iEntry)
						{
							GENERAL_NAME const* pName = sk_GENERAL_NAME_value(pSubjectAltNames, iEntry);
							if (!pName)
								continue;

							unsigned char* pBuffer = nullptr;

							switch (pName->type)
							{
							case GEN_DNS:
							case GEN_URI:
							case GEN_EMAIL:
								ASN1_STRING_to_UTF8((unsigned char**)&pBuffer, pName->d.ia5);
								if (pBuffer)
								{
									auto Cleanup = g_OnScopeExit / [&]
										{
											OPENSSL_free(pBuffer);
										}
									;
									lHostnames.f_Insert(NStr::CStr(pBuffer));
								}
								break;
							case GEN_IPADD:
								{
									pBuffer = pName->d.ip->data;
									NStr::CStr IPAddress;

									if (pName->d.ip->length == 4)
										IPAddress = NStr::CStr::CFormat("{}.{}.{}.{}") << pBuffer[0] << pBuffer[1] << pBuffer[2] << pBuffer[3];
									else if (pName->d.ip->length == 16)
									{
										for (int i = 0; i < 8; ++i)
										{
											if (IPAddress.f_IsEmpty())
												IPAddress += NStr::CStr::CFormat("{nfh,sj8,sf0}") << (pBuffer[0] << 8 | pBuffer[1]);
											else
												IPAddress += NStr::CStr::CFormat(":{nfh,sj8,sf0}") << (pBuffer[0] << 8 | pBuffer[1]);

											pBuffer += 2;
										}
									}

									if (!IPAddress.f_IsEmpty())
										lHostnames.f_Insert(IPAddress);
								}
								break;
							}
						}
					}

					// Fallback on the common name of the certificate
					if (_bCheckCommonName)
					{
						X509_NAME* pSubject = X509_get_subject_name(pCertificate);
						if (pSubject)
						{
							char CommonName[256];
							int nChars = X509_NAME_get_text_by_NID(pSubject, NID_commonName, CommonName, sizeof(CommonName));
							if (nChars > 0)
								lHostnames.f_Insert(NStr::CStr(CommonName, nChars));
						}
					}

					return lHostnames;
				}
			)
		;
	}

	NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> CCertificate::fs_GetCertificateExtensions(NContainer::CByteVector const &_CertificateData)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_free(pCertificate);
						}
					;

					ERR_clear_error();
					int nExtensions = X509_get_ext_count(pCertificate);

					NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> Return;

					for (int iExtension = 0; iExtension < nExtensions; ++iExtension)
					{
						auto *pExtension = X509_get_ext(pCertificate, iExtension);
						if (!pExtension)
							continue;

						NStr::CStr Name;
						CCertificateExtension Extension;
						if (!fg_DecodeExtension(pExtension, Name, Extension))
							continue;

						Return[Name].f_Insert(fg_Move(Extension));
					}

					return Return;
				}
			)
		;
	}

	NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> CCertificate::fs_GetCertificateRequestExtensions
		(
			NContainer::CByteVector const &_CertificateRequestData
		)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>>
				{
					X509_REQ *pCertificateRequest = fg_LoadCertificateRequest(_CertificateRequestData);
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_REQ_free(pCertificateRequest);
						}
					;

					ERR_clear_error();

					auto pExtensions = X509_REQ_get_extensions(pCertificateRequest);
					auto Cleanup = g_OnScopeExit / [&]
						{
							if (pExtensions)
								sk_X509_EXTENSION_pop_free(pExtensions, X509_EXTENSION_free);
						}
					;

					if (!pExtensions)
						return fg_Default();

					ERR_clear_error();
					int nExtensions = X509v3_get_ext_count(pExtensions);
					if (nExtensions < 0)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to get extension count from certificate request"));

					NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> Return;

					for (int iExtension = 0; iExtension < nExtensions; ++iExtension)
					{
						auto *pExtension = X509v3_get_ext(pExtensions, iExtension);
						if (!pExtension)
							continue;

						NStr::CStr Name;
						CCertificateExtension Extension;
						if (!fg_DecodeExtension(pExtension, Name, Extension))
							continue;

						Return[Name].f_Insert(fg_Move(Extension));
					}

					return Return;
				}
			)
		;
	}

	NContainer::TCVector<NStr::CStr> CCertificate::fs_GetSortedHostnames(NContainer::TCVector<NStr::CStr> const &_Unsorted)
	{
		NContainer::TCVector<NStr::CStr> Sorted;
		for (auto Iter = _Unsorted.f_GetIterator(); Iter; ++Iter)
		{
			if (Sorted.f_Contains(*Iter) == -1 && !(*Iter).f_IsEmpty())
				Sorted.f_Insert(*Iter);
		}

		Sorted.f_Sort();
		return Sorted;
	}

	NStr::CStr CCertificate::fs_GetCertificateHostnamesStr(NContainer::CByteVector const &_CertificateData)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					NStr::CStr Hostnames;
					NContainer::TCVector<NStr::CStr> lHostNames = fs_GetCertificateHostnames(_CertificateData);
					for (auto Iter = lHostNames.f_GetIterator(); Iter; ++Iter)
					{
						if (Hostnames.f_IsEmpty())
							Hostnames = (*Iter);
						else
							Hostnames += ", " + (*Iter);
					}

					if (Hostnames.f_IsEmpty())
						Hostnames = "-";

					return Hostnames;
				}
			)
		;
	}

	NTime::CTime CCertificate::fs_GetCertificateExpirationTime(NContainer::CByteVector const &_CertificateData)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_free(pCertificate);
						}
					;

					return fg_ConvertFromASN1Time(X509_get_notAfter(pCertificate));
				}
			)
		;
	}

	NTime::CTime CCertificate::fs_GetCertificateIssueTime(NContainer::CByteVector const &_CertificateData)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_free(pCertificate);
						}
					;

					return fg_ConvertFromASN1Time(X509_get_notBefore(pCertificate));
				}
			)
		;
	}

	NStr::CStr CCertificate::fs_GetCertificateInformation(NContainer::CByteVector const &_CertificateData)
	{
		auto CertificateData = _CertificateData;
		if (!CertificateData.f_IsEmpty())
		{
			CertificateData[CertificateData.f_GetLen() - 1] = '\0';
			return NStr::CStr((ch8 const *)CertificateData.f_GetArray());
		}

		return NStr::CStr();
	}

	NContainer::CSecureByteVector CCertificate::fs_GetCertificatePublicKey(NContainer::CByteVector const &_CertificateData)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_free(pCertificate);
						}
					;

					ERR_clear_error();
					EVP_PKEY *pKey = X509_get_pubkey(pCertificate);
					if (!pKey)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to read certificate public key"));
					auto Cleanup1 = g_OnScopeExit / [&]
						{
							EVP_PKEY_free(pKey);
						}
					;

					return fg_ConvertPublicKeyToDER(pKey);
				}
			)
		;
	}

	bool CCertificate::fs_VerifyCertificateChain
		(
			NContainer::TCVector<NContainer::CByteVector> const &_CertificateChain
			, NContainer::CByteVector const &_CACertificateData
			, bool _bUseSystemStoreIfNoCA
			, EVerificationPurpose _RequiredPurpose
			, CCertificateVerifyOptions const &_VerifyOptions
			, NContainer::TCVector<NContainer::CByteVector> *o_pVerifiedChain
			, NStr::CStr &o_Error
		)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> bool
				{
					// Never leave a stale message from a previous call behind a success result
					o_Error.f_Clear();

					if (_CertificateChain.f_IsEmpty())
					{
						o_Error = "Empty certificate chain";
						return false;
					}

					ERR_clear_error();
					X509_STORE *pStore = X509_STORE_new();
					if (!pStore)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to create certificate store"));
					auto Cleanup0 = g_OnScopeExit / [&]
						{
							X509_STORE_free(pStore);
						}
					;

					if (!_CACertificateData.f_IsEmpty())
					{
						X509 *pCACertificate = fg_LoadCertificate(_CACertificateData);
						auto Cleanup1 = g_OnScopeExit / [&]
							{
								X509_free(pCACertificate);
							}
						;

						ERR_clear_error();
						if (!X509_STORE_add_cert(pStore, pCACertificate))
							DMibErrorCryptography(fg_GetExceptionStr("Failed to add CA certificate to store"));
					}
					else if (_bUseSystemStoreIfNoCA)
						fs_GetSystemCertificates(pStore);
					else
					{
						o_Error = "No certificate authority to verify against";
						return false;
					}

					X509 *pLeafCertificate = fg_LoadCertificate(_CertificateChain[0]);
					auto Cleanup2 = g_OnScopeExit / [&]
						{
							X509_free(pLeafCertificate);
						}
					;

					// A critical extension the library does not implement must fail verification per
					// X.509. The store context only applies this check to the untrusted part of the
					// path, so a leaf that is its own trust anchor (pinned directly as the CA) would
					// skip it; check the leaf here for every purpose including Any
					if (X509_get_extension_flags(pLeafCertificate) & EXFLAG_CRITICAL)
					{
						o_Error = "Certificate contains an unsupported critical extension";
						return false;
					}

					// A recognized extension that fails to decode marks the certificate invalid and is
					// skipped by the store context in the same leaf-as-anchor case, so it is checked
					// directly as well
					if (X509_get_extension_flags(pLeafCertificate) & EXFLAG_INVALID)
					{
						o_Error = "Certificate contains an invalid extension";
						return false;
					}

					if (_RequiredPurpose != EVerificationPurpose_Any)
					{
						// Check the leaf directly: the store context purpose check does not cover a leaf
						// that is its own trust anchor, because path building substitutes the trusted
						// store copy and only applies the purpose to the remaining chain entries
						int Purpose = _RequiredPurpose == EVerificationPurpose_ServerAuth ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT;

						ERR_clear_error();
						if (X509_check_purpose(pLeafCertificate, Purpose, 0) != 1)
						{
							o_Error = _RequiredPurpose == EVerificationPurpose_ServerAuth
								? "Certificate is not valid for server authentication"
								: "Certificate is not valid for client authentication"
							;
							return false;
						}

						// A present extended key usage extension must include the exact role usage.
						// X509_check_purpose alone also accepts legacy equivalents (for example the
						// Netscape/Microsoft server-gated-crypto usages for the server purpose), which
						// this contract does not
						if (X509_get_extension_flags(pLeafCertificate) & EXFLAG_XKUSAGE)
						{
							uint32_t RequiredUsage = _RequiredPurpose == EVerificationPurpose_ServerAuth ? XKU_SSL_SERVER : XKU_SSL_CLIENT;
							if (!(X509_get_extended_key_usage(pLeafCertificate) & RequiredUsage))
							{
								o_Error = _RequiredPurpose == EVerificationPurpose_ServerAuth
									? "Certificate extended key usage does not include server authentication"
									: "Certificate extended key usage does not include client authentication"
								;
								return false;
							}
						}

						// Both roles authenticate by producing a signature, so a key usage extension
						// must include digitalSignature; the TLS purposes alone also accept key
						// exchange only usages (keyEncipherment/keyAgreement), which cannot sign.
						// X509_get_key_usage returns all bits set when no extension is present
						if (!(X509_get_key_usage(pLeafCertificate) & X509v3_KU_DIGITAL_SIGNATURE))
						{
							o_Error = "Certificate key usage does not allow digital signatures";
							return false;
						}

						// An absent key usage extension reports all usages, so the key algorithm is
						// also checked directly: only algorithms that can produce signatures qualify
						// (X25519 is key agreement only)
						EVP_PKEY *pLeafSigningKey = X509_get0_pubkey(pLeafCertificate);
						int LeafKeyType = pLeafSigningKey ? EVP_PKEY_id(pLeafSigningKey) : NID_undef;
						if (LeafKeyType != EVP_PKEY_RSA && LeafKeyType != EVP_PKEY_EC && LeafKeyType != EVP_PKEY_ED25519)
						{
							o_Error = "Certificate public key type cannot produce signatures";
							return false;
						}
					}

					// The verification whitelists mirror the issuance whitelists: the caller states
					// which key types and signature digests its protocol issues, and any other leaf is
					// rejected regardless of who signed it
					if (!_VerifyOptions.m_AllowedLeafKeyTypes.f_IsEmpty())
					{
						EVP_PKEY *pLeafPublicKey = X509_get0_pubkey(pLeafCertificate);
						if (!pLeafPublicKey || !fg_KeyMatchesAllowedSetting(pLeafPublicKey, _VerifyOptions.m_AllowedLeafKeyTypes))
						{
							o_Error = "Certificate public key type is not allowed";
							return false;
						}
					}

					if (!_VerifyOptions.m_AllowedSignatureDigests.f_IsEmpty())
					{
						ASN1_BIT_STRING const *pSignature = nullptr;
						X509_ALGOR const *pSignatureAlgorithm = nullptr;
						X509_get0_signature(&pSignature, &pSignatureAlgorithm, pLeafCertificate);

						if (!fg_DigestNIDMatchesAllowed(fg_GetSignatureDigestNID(pSignatureAlgorithm), _VerifyOptions.m_AllowedSignatureDigests))
						{
							o_Error = "Certificate signature digest is not allowed";
							return false;
						}
					}

					ERR_clear_error();
					STACK_OF(X509) *pUntrusted = sk_X509_new_null();
					if (!pUntrusted)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to create certificate stack"));
					auto Cleanup3 = g_OnScopeExit / [&]
						{
							sk_X509_pop_free(pUntrusted, X509_free);
						}
					;

					for (umint i = 1; i < _CertificateChain.f_GetLen(); ++i)
					{
						X509 *pIntermediate = fg_LoadCertificate(_CertificateChain[i]);

						ERR_clear_error();
						if (!sk_X509_push(pUntrusted, pIntermediate))
						{
							X509_free(pIntermediate);
							DMibErrorCryptography(fg_GetExceptionStr("Failed to add certificate to stack"));
						}
					}

					ERR_clear_error();
					X509_STORE_CTX *pContext = X509_STORE_CTX_new();
					if (!pContext)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to create certificate store context"));
					auto Cleanup4 = g_OnScopeExit / [&]
						{
							X509_STORE_CTX_free(pContext);
						}
					;

					ERR_clear_error();
					if (!X509_STORE_CTX_init(pContext, pStore, pLeafCertificate, pUntrusted))
						DMibErrorCryptography(fg_GetExceptionStr("Failed to initialize certificate store context"));

					// A caller-supplied CA is an explicit trust anchor even when it is a CA-issued leaf
					// or intermediate pinned directly, so path building may stop at the store match
					// instead of requiring a self-signed root. For the system store this depends on
					// the platform: on macOS every loaded certificate is an anchor by keychain trust
					// settings (including trust-as-root entries that are not self-signed and need
					// partial chain handling to anchor at all), while the Windows store also carries
					// chain-building intermediates from its CA store, which are not independently
					// trusted and must still chain to a root
					if (!_CACertificateData.f_IsEmpty() || fs_SystemStoreCertificatesAreAnchors())
						X509_STORE_CTX_set_flags(pContext, X509_V_FLAG_PARTIAL_CHAIN);

					// Constrain the rest of the path to the requested role; the leaf itself was already
					// checked directly above (the store context skips a leaf that is its own anchor)
					if (_RequiredPurpose != EVerificationPurpose_Any)
					{
						int Purpose = _RequiredPurpose == EVerificationPurpose_ServerAuth ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT;

						ERR_clear_error();
						if (!X509_STORE_CTX_set_purpose(pContext, Purpose))
							DMibErrorCryptography(fg_GetExceptionStr("Failed to set certificate verification purpose"));
					}

					ERR_clear_error();
					if (X509_verify_cert(pContext) != 1)
					{
						o_Error = X509_verify_cert_error_string(X509_STORE_CTX_get_error(pContext));

						return false;
					}

					// BoringSSL's path length checking iterates only the untrusted certificates, so a
					// pathlen constraint on the trust anchor itself is never consulted there; enforce
					// it here so a pathlen:0 anchor really forbids intermediates below it. Following
					// the pathlen definition (and BoringSSL's own check for non-anchor constraints),
					// self-issued intermediates do not count toward the limit
					{
						STACK_OF(X509) *pBuiltChain = X509_STORE_CTX_get0_chain(pContext);
						size_t nChain = sk_X509_num(pBuiltChain);
						if (nChain >= 2)
						{
							X509 *pAnchor = sk_X509_value(pBuiltChain, nChain - 1);

							// The store context also never examines the anchor's extensions, so a
							// trust anchor carrying an unrecognized critical extension or one that
							// fails to decode must be rejected here, per the trust anchor constraint
							// processing in RFC 5937 (the leaf-as-anchor case is checked directly at
							// the top of this function)
							if (X509_get_extension_flags(pAnchor) & EXFLAG_CRITICAL)
							{
								o_Error = "Trust anchor contains an unsupported critical extension";
								return false;
							}

							if (X509_get_extension_flags(pAnchor) & EXFLAG_INVALID)
							{
								o_Error = "Trust anchor contains an invalid extension";
								return false;
							}

							long nIntermediates = 0;
							for (size_t i = 1; i + 1 < nChain; ++i)
							{
								if (!(X509_get_extension_flags(sk_X509_value(pBuiltChain, i)) & EXFLAG_SI))
									++nIntermediates;
							}

							long AnchorPathLen = X509_get_pathlen(pAnchor);
							if (AnchorPathLen >= 0 && nIntermediates > AnchorPathLen)
							{
								o_Error = "Certificate chain is longer than the trust anchor's path length constraint allows";
								return false;
							}
						}
					}

					if (o_pVerifiedChain)
					{
						// Return the path that verification actually built (leaf first, up to the trust
						// anchor); it may differ from the input when the store supplied the path or the
						// input carried extra certificates
						o_pVerifiedChain->f_Clear();

						STACK_OF(X509) *pVerifiedChain = X509_STORE_CTX_get0_chain(pContext);
						for (size_t i = 0; i < sk_X509_num(pVerifiedChain); ++i)
							o_pVerifiedChain->f_Insert(fg_ConvertX509ToBinary(sk_X509_value(pVerifiedChain, i)));
					}

					return true;
				}
			)
		;
	}
}
