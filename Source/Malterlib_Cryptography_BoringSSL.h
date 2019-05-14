#pragma once

#include "Malterlib_Cryptography_SymmetricCrypto.h"
#include "Malterlib_Cryptography_Certificate.h"

extern "C"
{
#	include <openssl/dh.h>
#	include <openssl/ssl.h>
#	include <openssl/evp.h>
#	include <openssl/aes.h>
#	include <openssl/err.h>
#	include <openssl/conf.h>
#	include <openssl/engine.h>
#	include <openssl/hkdf.h>
#	undef X509_NAME
#	include <openssl/x509v3.h>

#ifdef DPlatformFamily_OSX
	#include <Security/Security.h>
#endif

};

#if defined(DPlatformFamily_Windows)

	#include <Windows.h>
	#include <Wincrypt.h>

	#undef X509_NAME
	#undef X509_EXTENSIONS
	#undef PKCS7_ISSUER_AND_SERIAL
	#undef OCSP_REQUEST
	#undef OCSP_RESPONSE

	#include <Mib/Core/PlatformSpecific/WindowsError>

	#pragma comment(lib, "crypt32.lib")

#else
	// Unix
	#include <Mib/Core/PlatformSpecific/PosixErrNo>
	#include <errno.h>

#endif

namespace NMib::NCryptography::NBoringSSL
{
	void fg_Init();
	NStr::CStr fg_GetErrors();
	NStr::CStr fg_GetExceptionStr(NStr::CStr const &_Description);
	EVP_CIPHER const *fg_GetCipher(ECryptoType _Crypto);
	EVP_MD const *fg_GetDigest(EDigestType _Digest);
	EVP_MD const *fg_GetDigest(EDigestType _Digest, EVP_PKEY *_pKey);
	EVP_PKEY *fg_LoadPrivateKeyFromDER(NContainer::CSecureByteVector const &_Data);
	EVP_PKEY *fg_LoadPublicKeyFromDER(NContainer::CSecureByteVector const &_Data);
	NContainer::CSecureByteVector fg_ConvertPrivateKeyToDER(EVP_PKEY *_pKey);
	NContainer::CSecureByteVector fg_ConvertPublicKeyToDER(EVP_PKEY *_pKey);
	void fg_GenerateKey(EVP_PKEY *_pKey, CCertificateOptions const &_Options);
	X509 *fg_LoadCertificate(NContainer::CByteVector const &_CertificateData);
	NContainer::CByteVector fg_ConvertX509ToBinary(X509 *_pCertificate);
	EVP_PKEY *fg_LoadPrivateKey(NContainer::CSecureByteVector const &_Data);
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif

#include "Malterlib_Cryptography_BoringSSL_RegisterProtect.h"
