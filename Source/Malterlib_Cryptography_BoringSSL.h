// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "Malterlib_Cryptography_SymmetricCrypto.h"
#include "Malterlib_Cryptography_Certificate.h"

extern "C"
{
#	include <openssl/dh.h>
#	include <openssl/bn.h>
#	include <openssl/ssl.h>
#	include <openssl/evp.h>
#	include <openssl/aes.h>
#	include <openssl/err.h>
#	include <openssl/conf.h>
#	include <openssl/engine.h>
#	include <openssl/hkdf.h>
#	undef X509_NAME
#	include <openssl/x509v3.h>

#ifdef DPlatformFamily_macOS
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
	X509_CRL *fg_LoadCrl(NContainer::CByteVector const &_CertificateData);
	NTime::CTime fg_ConvertFromASN1Time(ASN1_TIME const *_pTime);
	NContainer::CByteVector fg_ConvertX509ToBinary(X509 *_pCertificate);
	NTime::CTime fg_GetX509ExpireTime(X509 *_pCertificate);
	EVP_PKEY *fg_LoadPrivateKey(NContainer::CSecureByteVector const &_Data);

	// True when the key matches one of the allowed settings; an RSA entry's key length is a
	// minimum, not an exact size
	bool fg_KeyMatchesAllowedSetting(EVP_PKEY *_pKey, NContainer::TCVector<CPublicKeySetting> const &_Allowed);

	// True when the digest NID (from OBJ_find_sigid_algs) matches one of the allowed digest types
	bool fg_DigestNIDMatchesAllowed(int _DigestNID, NContainer::TCVector<EDigestType> const &_Allowed);

	// Resolves the message digest NID from a signature algorithm identifier. For RSASSA-PSS the
	// digest is carried in the algorithm parameters rather than the signature OID, so it is decoded
	// from the RSA_PSS_PARAMS; returns NID_undef when it cannot be determined
	int fg_GetSignatureDigestNID(X509_ALGOR const *_pSignatureAlgorithm);
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif

#include "Malterlib_Cryptography_BoringSSL_RegisterProtect.h"
