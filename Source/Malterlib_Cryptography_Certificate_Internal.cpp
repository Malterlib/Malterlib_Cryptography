// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Cryptography_Certificate.h"
#include "Malterlib_Cryptography_Certificate_Internal.h"

#include <Mib/Cryptography/BoringSSL>

namespace NMib::NCryptography::NBoringSSL
{
	bool fg_DecodeExtension(X509_EXTENSION *_pExtension, NStr::CStr &o_Name, CCertificateExtension &o_Extension)
	{
		ASN1_OBJECT *pObject = X509_EXTENSION_get_object(_pExtension);
		ASN1_OCTET_STRING *pData = X509_EXTENSION_get_data(_pExtension);
		int Critical = X509_EXTENSION_get_critical(_pExtension);

		NStr::CStr Name;
		int nID = OBJ_obj2nid(pObject);
		if (nID != NID_undef)
		{
			const char *pShortName = OBJ_nid2sn(nID);
			if (pShortName)
			{
				Name = pShortName;
			}
		}
		if (Name.f_IsEmpty())
		{
			ch8 Data[1024];
			Data[0] = 0;
			OBJ_obj2txt(Data, 1024, pObject, 0);
			Data[1023] = 0;
			Name = Data;
		}

		if (Name.f_IsEmpty())
			return false;

		NStr::CStr Value;
		switch (pData->type)
		{
		case V_ASN1_NUMERICSTRING:
		case V_ASN1_PRINTABLESTRING:
		case V_ASN1_UTF8STRING:
		case V_ASN1_T61STRING:
		case V_ASN1_VIDEOTEXSTRING:
		case V_ASN1_ISO64STRING:
		case V_ASN1_IA5STRING:
		case V_ASN1_OCTET_STRING:
			{
				Value = NStr::CStr((ch8 const *)pData->data, pData->length);
			}
			break;
		default:
			return false;
		}

		o_Name = fg_Move(Name);
		o_Extension.m_Value = fg_Move(Value);
		o_Extension.m_bCritical = Critical != 0;

		return true;
	}

	X509_REQ *fg_LoadCertificateRequest(NContainer::CByteVector const &_CertificateRequestData)
	{
		if (_CertificateRequestData.f_IsEmpty())
			DMibErrorCryptography("Empty certificate request data");

		ERR_clear_error();
		BIO* pMemoryBio = BIO_new_mem_buf( const_cast<void*>(static_cast<void const *>(_CertificateRequestData.f_GetArray())), _CertificateRequestData.f_GetLen());
		if (!pMemoryBio)
			DMibErrorCryptography(fg_GetExceptionStr("Error creating BIO buffer"));
		auto Cleanup = g_OnScopeExit / [&]
			{
				BIO_free(pMemoryBio);
			}
		;

		X509_REQ *pCertificateRequest = nullptr;
		ERR_clear_error();
		pCertificateRequest = PEM_read_bio_X509_REQ(pMemoryBio, nullptr, nullptr, nullptr);
		if (!pCertificateRequest)
			DMibErrorCryptography(fg_GetExceptionStr("Error reading x509 certificate request"));

		return pCertificateRequest;
	}

	NContainer::CSecureByteVector fg_ConvertKeyToBinary(EVP_PKEY *_pKey)
	{
		if (!_pKey)
			DMibErrorCryptography("Key in nullptr");

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
		if (!PEM_write_bio_PrivateKey(pMemoryBio, _pKey, nullptr, nullptr, 0, nullptr, nullptr))
			DMibErrorCryptography(fg_GetExceptionStr("Error writing private key to BIO"));

		NContainer::CSecureByteVector Return;
		Return.f_SetLen(BIO_number_written(pMemoryBio));
		ERR_clear_error();
		if (!BIO_read(pMemoryBio, Return.f_GetArray(), Return.f_GetLen()))
			DMibErrorCryptography(fg_GetExceptionStr("Error reading private key from BIO"));
		return Return;
	}

	NContainer::CByteVector fg_ConvertX509RequestToBinary(X509_REQ *_pCertificateRequest)
	{
		if (!_pCertificateRequest)
			DMibErrorCryptography("x509 certificate request in nullptr");

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
		if (!PEM_write_bio_X509_REQ(pMemoryBio, _pCertificateRequest))
			DMibErrorCryptography(fg_GetExceptionStr("Error writing request to BIO"));

		NContainer::CByteVector Return;
		Return.f_SetLen(BIO_number_written(pMemoryBio));
		ERR_clear_error();
		if (!BIO_read(pMemoryBio, Return.f_GetArray(), Return.f_GetLen()))
			DMibErrorCryptography(fg_GetExceptionStr("Error reading request from BIO"));
		return Return;
	}
}
