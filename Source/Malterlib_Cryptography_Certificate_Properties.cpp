#include "Malterlib_Cryptography_Certificate.h"
#include "Malterlib_Cryptography_Certificate_Internal.h"

#include <Mib/Cryptography/BoringSSL>

namespace NMib::NCryptography
{
	using namespace NBoringSSL;

	NStr::CStr CCertificate::fs_GetCertificateDescription(NContainer::CByteVector const &_CertificateData)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					NStr::CStr CertificateDescription;
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit > [&]
						{
							X509_free(pCertificate);
						}
					;

					ERR_clear_error();
					BIO* pMemoryBio = BIO_new(BIO_s_mem());
					if (!pMemoryBio)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to create BIO"));
					auto Cleanup1 = g_OnScopeExit > [&]
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
					auto Cleanup0 = g_OnScopeExit > [&]
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
					auto Cleanup0 = g_OnScopeExit > [&]
						{
							X509_free(pCertificate);
						}
					;

					ERR_clear_error();
					BIO* pMemoryBio = BIO_new(BIO_s_mem());
					if (!pMemoryBio)
						DMibErrorCryptography(fg_GetExceptionStr("Error creating BIO"));
					auto Cleanup = g_OnScopeExit > [&]
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
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit > [&]
						{
							X509_free(pCertificate);
						}
					;

					unsigned int DigestSize = 0;
					unsigned char Digest[EVP_MAX_MD_SIZE];
					if (!X509_digest(pCertificate, EVP_sha256(), Digest, &DigestSize))
						DMibErrorCryptography(fg_GetExceptionStr("Failed to calculate certificate digest"));

					NStr::CStr Fingerprint;
					for (mint iByte = 0; iByte < DigestSize; ++iByte)
						Fingerprint += NStr::CStr::CFormat("{nh,sf0,sf2}") << Digest[iByte];

					return Fingerprint;
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
					auto Cleanup0 = g_OnScopeExit > [&]
						{
							X509_free(pCertificate);
						}
					;
					char Buffer[256];
					ERR_clear_error();
					int nChars = X509_NAME_get_text_by_NID(X509_get_issuer_name(pCertificate), NID_commonName, Buffer, 256);
					if (nChars < 0)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to read certificate issuen name"));
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
					auto Cleanup0 = g_OnScopeExit > [&]
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
						auto Cleanup = g_OnScopeExit > [&]
							{
								GENERAL_NAMES_free(pSubjectAltNames);
							}
						;
						mint nAltEntries = sk_GENERAL_NAME_num(pSubjectAltNames);

						for (mint iEntry = 0; iEntry < nAltEntries; ++iEntry)
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
									auto Cleanup = g_OnScopeExit > [&]
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
					auto Cleanup0 = g_OnScopeExit > [&]
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
					auto Cleanup0 = g_OnScopeExit > [&]
						{
							X509_REQ_free(pCertificateRequest);
						}
					;

					ERR_clear_error();

					auto pExtensions = X509_REQ_get_extensions(pCertificateRequest);
					auto Cleanup = g_OnScopeExit > [&]
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

	namespace
	{
		bool fg_IsValidDateTime(int _Years, int _Months, int _Days, int _Hours, int _Minutes, int _Seconds)
		{
			return fg_Clamp(_Months, 1, 12) == _Months
				&& fg_Clamp(_Days, 1, NTime::CTimeConvert::fs_GetDaysInMonth(_Years, _Months - 1)) == _Days
				&& fg_Clamp(_Hours, 0, 23) == _Hours
				&& fg_Clamp(_Minutes, 0, 59) == _Minutes
				&& fg_Clamp(_Seconds, 0, 59) == _Seconds
			;
		}

		NTime::CTime fg_ConvertFromASN1Time(ASN1_TIME const *_pTime)
		{
			if (!_pTime)
				return NTime::CTime::fs_StartOfTime();

			if (_pTime->type == V_ASN1_UTCTIME)
			{
				if (_pTime->length < 10)
					return NTime::CTime::fs_StartOfTime();

				ch8 const *pData = (ch8 const *)_pTime->data;

				for (int i = 0; i < 10; ++i)
				{
					if (!NStr::fg_CharIsNumber(pData[i]))
						return NTime::CTime::fs_StartOfTime();
				}

				int Years = (pData[0] - '0') * 10 + (pData[1] - '0');
				if (Years < 50)
					Years += 100;
				Years += 1900;

				int Months = (pData[2] - '0') * 10 + (pData[3] - '0');
				int Days = (pData[4] - '0') * 10 + (pData[5] - '0');
				int Hours = (pData[6] - '0') * 10 + (pData[7] - '0');
				int Minutes = (pData[8] - '0') * 10 + (pData[9] - '0');
				int Seconds = 0;

				if (_pTime->length >= 12 && NStr::fg_CharIsNumber(pData[10]) && NStr::fg_CharIsNumber(pData[11]))
					Seconds = (pData[10] - '0') * 10 + (pData[11] - '0');

				if (!fg_IsValidDateTime(Years, Months, Days, Hours, Minutes, Seconds))
					return NTime::CTime::fs_StartOfTime();

				return NTime::CTimeConvert::fs_CreateTime(Years, Months, Days, Hours, Minutes, Seconds);
			}
			else if (_pTime->type == V_ASN1_GENERALIZEDTIME)
			{
				if (_pTime->length < 12)
					return NTime::CTime::fs_StartOfTime();

				ch8 const *pData = (ch8 const *)_pTime->data;

				for (int i = 0; i < 12; ++i)
				{
					if (!NStr::fg_CharIsNumber(pData[i]))
						return NTime::CTime::fs_StartOfTime();
				}

				int Years = (pData[0] - '0') * 1000 + (pData[1] - '0') * 100 + (pData[2] - '0') * 10 + (pData[3] - '0');
				int Months = (pData[4] - '0') * 10 + (pData[5] - '0');
				int Days = (pData[6] - '0') * 10 + (pData[7] - '0');
				int Hours = (pData[8] - '0') * 10 + (pData[9] - '0');
				int Minutes = (pData[10] - '0') * 10 + (pData[11] - '0');
				int Seconds = 0;

				if (_pTime->length >= 14 && NStr::fg_CharIsNumber(pData[12]) && NStr::fg_CharIsNumber(pData[13]))
					Seconds = (pData[12] - '0') * 10 + (pData[13] - '0');

				if (!fg_IsValidDateTime(Years, Months, Days, Hours, Minutes, Seconds))
					return NTime::CTime::fs_StartOfTime();

				return NTime::CTimeConvert::fs_CreateTime(Years, Months, Days, Hours, Minutes, Seconds);
			}

			return NTime::CTime::fs_StartOfTime();
		}
	}

	NTime::CTime CCertificate::fs_GetCertificateExpirationTime(NContainer::CByteVector const &_CertificateData)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					X509 *pCertificate = fg_LoadCertificate(_CertificateData);
					auto Cleanup0 = g_OnScopeExit > [&]
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
					auto Cleanup0 = g_OnScopeExit > [&]
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
}
