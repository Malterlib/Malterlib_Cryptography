#pragma once
#include "Malterlib_Cryptography_BoringSSL.h"

namespace NMib::NCryptography::NBoringSSL
{
	bool fg_DecodeExtension(X509_EXTENSION *_pExtension, NStr::CStr &o_Name, CCertificateExtension &o_Extension);
	X509_REQ *fg_LoadCertificateRequest(NContainer::CByteVector const &_CertificateRequestData);
	NContainer::CSecureByteVector fg_ConvertKeyToBinary(EVP_PKEY *_pKey);
	NContainer::CByteVector fg_ConvertX509RequestToBinary(X509_REQ *_pCertificateRequest);
}
