// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Cryptography_Timestamp.h"
#include "Malterlib_Cryptography_BoringSSL.h"
#include "Malterlib_Cryptography_Certificate.h"
#include "Malterlib_Cryptography_Exception.h"

#include <openssl/asn1.h>
#include <openssl/bytestring.h>
#include <openssl/evp.h>
#include <openssl/obj.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstring>
#include <limits>

using namespace NMib;
using namespace NMib::NCryptography;
using namespace NMib::NCryptography::NBoringSSL;
using namespace NMib::NStr;

namespace
{
	constexpr char const *mc_Oid_Pkcs9ContentType = "1.2.840.113549.1.9.3";
	constexpr char const *mc_Oid_Pkcs9MessageDigest = "1.2.840.113549.1.9.4";
	constexpr char const *mc_Oid_SigningCertificate = "1.2.840.113549.1.9.16.2.12";
	constexpr char const *mc_Oid_SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";
	constexpr char const *mc_Oid_TSTInfo = "1.2.840.113549.1.9.16.1.4";

#ifdef NID_pkcs9_contentType
	constexpr int mc_NidPkcs9ContentType = NID_pkcs9_contentType;
#else
	constexpr int mc_NidPkcs9ContentType = NID_undef;
#endif

#ifdef NID_pkcs9_messageDigest
	constexpr int mc_NidPkcs9MessageDigest = NID_pkcs9_messageDigest;
#else
	constexpr int mc_NidPkcs9MessageDigest = NID_undef;
#endif

#ifdef NID_id_smime_aa_signingCertificate
	constexpr int mc_NidSigningCertificate = NID_id_smime_aa_signingCertificate;
#else
	constexpr int mc_NidSigningCertificate = NID_undef;
#endif

#ifdef NID_id_smime_aa_signingCertificateV2
	constexpr int mc_NidSigningCertificateV2 = NID_id_smime_aa_signingCertificateV2;
#else
	constexpr int mc_NidSigningCertificateV2 = NID_undef;
#endif

#ifdef NID_id_smime_ct_TSTInfo
	constexpr int mc_NidTstInfo = NID_id_smime_ct_TSTInfo;
#else
	constexpr int mc_NidTstInfo = NID_undef;
#endif

	// Helper: Convert OID NID to digest type
	EDigestType fg_NIDToDigestType(int _nNID)
	{
		switch (_nNID)
		{
			case NID_md5: return EDigestType_MD5;
			case NID_sha1: return EDigestType_SHA1;
			case NID_sha256: return EDigestType_SHA256;
			case NID_sha384: return EDigestType_SHA384;
			case NID_sha512: return EDigestType_SHA512;
			default: return EDigestType_None;
		}
	}

	struct CParsedGeneralizedTime
	{
		NStr::CStr m_Raw;
		NTime::CTime m_Time;
	};

	bool fg_IsValidDateTimeComponents(int _Year, int _Month, int _Day, int _Hour, int _Minute, int _Second)
	{
		if (_Month < 1 || _Month > 12)
			return false;
		if (_Day < 1)
			return false;
		if (_Hour < 0 || _Hour > 23)
			return false;
		if (_Minute < 0 || _Minute > 59)
			return false;
		if (_Second < 0 || _Second > 59)
			return false;

		aint DaysInMonth = NTime::CTimeConvert::fs_GetDaysInMonth(_Year, _Month - 1);
		return _Day <= DaysInMonth;
	}

	CParsedGeneralizedTime fg_ParseGeneralizedTime(CBS *_pCBS)
	{
		CBS timeValue;
		if (!CBS_get_asn1(_pCBS, &timeValue, CBS_ASN1_GENERALIZEDTIME))
			DMibErrorCryptography("Failed to parse GeneralizedTime");

		if (CBS_len(&timeValue) < 15)
			DMibErrorCryptography("GeneralizedTime too short");

		ch8 const *pData = reinterpret_cast<ch8 const *>(CBS_data(&timeValue));
		size_t nLen = CBS_len(&timeValue);

		if (pData[nLen - 1] != 'Z')
			DMibErrorCryptography("GeneralizedTime must be expressed in UTC (suffix Z)");

		auto ParseComponent = [&](size_t _Offset, size_t _Count) -> int
		{
			int Value = 0;
			for (size_t i = 0; i < _Count; ++i)
			{
				ch8 Ch = pData[_Offset + i];
				if (Ch < '0' || Ch > '9')
					DMibErrorCryptography("GeneralizedTime contains non-numeric characters");
				Value = Value * 10 + (Ch - '0');
			}
			return Value;
		};

		int Year = ParseComponent(0, 4);
		int Month = ParseComponent(4, 2);
		int Day = ParseComponent(6, 2);
		int Hour = ParseComponent(8, 2);
		int Minute = ParseComponent(10, 2);
		int Second = ParseComponent(12, 2);

		fp64 Fraction = 0.0;
		if (nLen > 15)
		{
			if (pData[14] != '.')
				DMibErrorCryptography("GeneralizedTime fractional seconds must use '.' separator");

			size_t FractionDigits = (nLen - 1) - 15;
			if (FractionDigits == 0)
				DMibErrorCryptography("GeneralizedTime fractional seconds missing digits");

			fp64 Divisor = 10.0;
			for (size_t i = 0; i < FractionDigits; ++i)
			{
				ch8 Ch = pData[15 + i];
				if (Ch < '0' || Ch > '9')
					DMibErrorCryptography("GeneralizedTime fractional seconds contain non-numeric characters");
				Fraction += fp64(Ch - '0') / Divisor;
				Divisor *= 10.0;
			}
		}

		if (!fg_IsValidDateTimeComponents(Year, Month, Day, Hour, Minute, Second))
			DMibErrorCryptography("GeneralizedTime contains invalid date or time components");

		NTime::CTime ParsedTime = NTime::CTimeConvert::fs_CreateTime(Year, Month, Day, Hour, Minute, Second, Fraction);
		if (!ParsedTime.f_IsValid())
			DMibErrorCryptography("Failed to convert GeneralizedTime to internal representation");

		CParsedGeneralizedTime Result;
		Result.m_Raw = NStr::CStr(pData, nLen);
		Result.m_Time = ParsedTime;
		return Result;
	}

	uint64 fg_ParseImplicitUnsignedInteger(CBS *_pCBS, int _nTag, uint64 _nMaxValue, char const *_pFieldName)
	{
		CBS Element;
		if (!CBS_get_asn1(_pCBS, &Element, CBS_ASN1_CONTEXT_SPECIFIC | _nTag))
			DMibErrorCryptography("{} missing"_f << _pFieldName);

		if (!CBS_is_unsigned_asn1_integer(&Element))
			DMibErrorCryptography("{} must be a non-negative integer"_f << _pFieldName);

		size_t nLen = CBS_len(&Element);
		if (nLen == 0)
			DMibErrorCryptography("{} must not be empty"_f << _pFieldName);
		if (nLen > sizeof(uint64))
			DMibErrorCryptography("{} is too large"_f << _pFieldName);

		uint64 Value = 0;
		unsigned char const *pData = CBS_data(&Element);
		for (size_t i = 0; i < nLen; ++i)
		{
			Value = (Value << 8) | pData[i];
			if (_nMaxValue != 0 && Value > _nMaxValue)
				DMibErrorCryptography("{} exceeds allowed maximum"_f << _pFieldName);
		}
		return Value;
	}

	NContainer::CByteVector fg_CreateDigest(EVP_MD const *_pDigest, unsigned char const *_pData, size_t _nLen)
	{
		if (!_pDigest)
			DMibErrorCryptography("Unsupported digest algorithm");

		int nExpectedLen = EVP_MD_size(_pDigest);
		if (nExpectedLen <= 0)
			DMibErrorCryptography("Invalid digest output size");

		NContainer::CByteVector Digest;
		Digest.f_SetLen(nExpectedLen);

		unsigned int nDigestLen = 0;
		if (EVP_Digest(_pData, _nLen, Digest.f_GetArray(), &nDigestLen, _pDigest, nullptr) != 1)
			DMibErrorCryptography(NBoringSSL::fg_GetExceptionStr("EVP_Digest failed"));

		Digest.f_SetLen(nDigestLen);
		return Digest;
	}

	NContainer::CByteVector fg_CreateDigest(EVP_MD const *_pDigest, CBS const &_Data)
	{
		return fg_CreateDigest(_pDigest, reinterpret_cast<unsigned char const *>(CBS_data(&_Data)), CBS_len(&_Data));
	}

	void fg_VerifyIssuerAndSerial(CBS const &_IssuerAndSerial, X509 *_pSignerCert, char const *_pContext)
	{
		CBS IssuerAndSerial = _IssuerAndSerial;

		CBS IssuerAndSerialContent;
		if (!CBS_get_asn1(&IssuerAndSerial, &IssuerAndSerialContent, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("{}: failed to parse issuerAndSerialNumber"_f << _pContext);
		if (CBS_len(&IssuerAndSerial) != 0)
			DMibErrorCryptography("{}: unexpected data after issuerAndSerialNumber"_f << _pContext);

		CBS Inner = IssuerAndSerialContent;

		CBS IssuerElement;
		if (!CBS_get_asn1_element(&Inner, &IssuerElement, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("{}: failed to parse issuer"_f << _pContext);

		unsigned char const *pIssuerData = CBS_data(&IssuerElement);
		X509_NAME *pIssuerName = d2i_X509_NAME(nullptr, &pIssuerData, CBS_len(&IssuerElement));
		if (!pIssuerName)
			DMibErrorCryptography("{}: failed to decode issuer name"_f << _pContext);

		auto CleanupIssuer = g_OnScopeExit / [&]
			{
				X509_NAME_free(pIssuerName);
			}
		;

		if (X509_NAME_cmp(pIssuerName, X509_get_issuer_name(_pSignerCert)) != 0)
			DMibErrorCryptography("{}: issuer does not match signer certificate"_f << _pContext);

		CBS SerialElement;
		if (!CBS_get_asn1_element(&Inner, &SerialElement, CBS_ASN1_INTEGER))
			DMibErrorCryptography("{}: failed to parse serial number"_f << _pContext);
		if (CBS_len(&Inner) != 0)
			DMibErrorCryptography("{}: unexpected data after serial number"_f << _pContext);

		unsigned char const *pSerialData = CBS_data(&SerialElement);
		ASN1_INTEGER *pSerial = d2i_ASN1_INTEGER(nullptr, &pSerialData, CBS_len(&SerialElement));
		if (!pSerial)
			DMibErrorCryptography("{}: failed to decode serial number"_f << _pContext);

		auto CleanupSerial = g_OnScopeExit / [&]
			{
				ASN1_INTEGER_free(pSerial);
			}
		;

			if (ASN1_INTEGER_cmp(pSerial, X509_get0_serialNumber(_pSignerCert)) != 0)
				DMibErrorCryptography("{}: serial number does not match signer certificate"_f << _pContext);
	}

	bool fg_SignerSidMatchesCert_IssuerAndSerial(CBS const &_SidElement, X509 *_pCert)
	{
		CBS IssuerAndSerial = _SidElement;

		CBS IssuerAndSerialContent;
		if (!CBS_get_asn1(&IssuerAndSerial, &IssuerAndSerialContent, CBS_ASN1_SEQUENCE))
			return false;
		if (CBS_len(&IssuerAndSerial) != 0)
			return false;

		CBS Inner = IssuerAndSerialContent;

		CBS IssuerElement;
		if (!CBS_get_asn1_element(&Inner, &IssuerElement, CBS_ASN1_SEQUENCE))
			return false;

		unsigned char const *pIssuerData = CBS_data(&IssuerElement);
		X509_NAME *pIssuerName = d2i_X509_NAME(nullptr, &pIssuerData, CBS_len(&IssuerElement));
		if (!pIssuerName)
			return false;

		auto CleanupIssuer = g_OnScopeExit / [&]
			{
				X509_NAME_free(pIssuerName);
			}
		;

		if (X509_NAME_cmp(pIssuerName, X509_get_issuer_name(_pCert)) != 0)
			return false;

		CBS SerialElement;
		if (!CBS_get_asn1_element(&Inner, &SerialElement, CBS_ASN1_INTEGER))
			return false;
		if (CBS_len(&Inner) != 0)
			return false;

		unsigned char const *pSerialData = CBS_data(&SerialElement);
		ASN1_INTEGER *pSerial = d2i_ASN1_INTEGER(nullptr, &pSerialData, CBS_len(&SerialElement));
		if (!pSerial)
			return false;

		auto CleanupSerial = g_OnScopeExit / [&]
			{
				ASN1_INTEGER_free(pSerial);
			}
		;

		return ASN1_INTEGER_cmp(pSerial, X509_get0_serialNumber(_pCert)) == 0;
	}

	bool fg_SignerSidMatchesCert_SubjectKeyIdentifier(NContainer::CByteVector const &_SignerSubjectKeyIdentifier, X509 *_pCert)
	{
		if (_SignerSubjectKeyIdentifier.f_IsEmpty())
			return false;

#if defined(NID_subject_key_identifier)
		ASN1_OCTET_STRING *pSubjectKeyIdentifier = static_cast<ASN1_OCTET_STRING *>(X509_get_ext_d2i(_pCert, NID_subject_key_identifier, nullptr, nullptr));
#else
		ASN1_OCTET_STRING *pSubjectKeyIdentifier = nullptr;
#endif
		if (!pSubjectKeyIdentifier)
			return false;

		auto CleanupSubjectKeyIdentifier = g_OnScopeExit / [&]
			{
				ASN1_OCTET_STRING_free(pSubjectKeyIdentifier);
			}
		;

		return _SignerSubjectKeyIdentifier.f_GetLen() == static_cast<size_t>(pSubjectKeyIdentifier->length) &&
			memcmp(_SignerSubjectKeyIdentifier.f_GetArray(), pSubjectKeyIdentifier->data, pSubjectKeyIdentifier->length) == 0;
	}

	class COidMatcher
	{
	public:
		COidMatcher(int _ActualNid, ASN1_OBJECT *_pObject)
			: m_ActualNid(_ActualNid)
			, mp_Object(_pObject)
		{
		}

		bool f_Equals(int _ExpectedNid, char const *_pExpectedOid)
		{
			if (_ExpectedNid != NID_undef && m_ActualNid == _ExpectedNid)
				return true;
			if (!_pExpectedOid)
				return false;
			f_EnsureOidString();
			return m_OidString == _pExpectedOid;
		}

		ch8 const *f_GetOidString()
		{
			f_EnsureOidString();
			return m_OidString.f_GetStr();
		}

	private:
		void f_EnsureOidString()
		{
			if (m_bHasOidString)
				return;
			ch8 Buffer[128];
			int nLen = OBJ_obj2txt(Buffer, sizeof(Buffer), mp_Object, 1);
			if (nLen <= 0)
				DMibErrorCryptography("Failed to convert OID to text");
			m_OidString = NStr::CStr(Buffer, nLen);
			m_bHasOidString = true;
		}

		int m_ActualNid = NID_undef;
		ASN1_OBJECT *mp_Object = nullptr;
		NStr::CStr m_OidString;
		bool m_bHasOidString = false;
	};
}

namespace NMib::NCryptography
{
	// Parse TSTInfo from PKCS7 SignedData timestamp token


	CTimestampInfo fg_ParseTimestampToken(NContainer::CByteVector const &_TimestampToken)
	{
		unsigned char const *pData = _TimestampToken.f_GetArray();
		PKCS7 *pPKCS7 = d2i_PKCS7(nullptr, &pData, _TimestampToken.f_GetLen());
		if (!pPKCS7)
			DMibErrorCryptography(NBoringSSL::fg_GetExceptionStr("Failed to parse PKCS7 timestamp token"));
		auto CleanupPKCS7 = g_OnScopeExit / [&]
			{
				PKCS7_free(pPKCS7);
			}
		;

		if (!PKCS7_type_is_signed(pPKCS7))
			DMibErrorCryptography("Timestamp token is not PKCS7 SignedData");

		CBS pkcs7CBS;
		CBS_init(&pkcs7CBS, pPKCS7->ber_bytes, pPKCS7->ber_len);

		CBS contentInfo, contentType, content;
		if (!CBS_get_asn1(&pkcs7CBS, &contentInfo, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("Failed to parse PKCS7 ContentInfo SEQUENCE");

		if (!CBS_get_asn1(&contentInfo, &contentType, CBS_ASN1_OBJECT))
			DMibErrorCryptography("Failed to parse PKCS7 contentType");

		if (!CBS_get_asn1(&contentInfo, &content, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0))
			DMibErrorCryptography("Failed to parse PKCS7 explicit content");

		CBS signedData;
		if (!CBS_get_asn1(&content, &signedData, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("Failed to parse SignedData SEQUENCE");

		CBS version;
		if (!CBS_get_asn1(&signedData, &version, CBS_ASN1_INTEGER))
			DMibErrorCryptography("Failed to parse SignedData version");

		CBS digestAlgorithms;
		if (!CBS_get_asn1(&signedData, &digestAlgorithms, CBS_ASN1_SET))
			DMibErrorCryptography("Failed to parse digestAlgorithms SET");

		CBS encapContentInfo, encapContentType;
		if (!CBS_get_asn1(&signedData, &encapContentInfo, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("Failed to parse encapContentInfo");

		if (!CBS_get_asn1(&encapContentInfo, &encapContentType, CBS_ASN1_OBJECT))
			DMibErrorCryptography("Failed to parse encapContentType");

		CBS tstInfoTagged;
		if (!CBS_get_asn1(&encapContentInfo, &tstInfoTagged, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0))
			DMibErrorCryptography("Failed to parse TSTInfo tagged content");

		CBS tstInfoOctetString;
		if (!CBS_get_asn1(&tstInfoTagged, &tstInfoOctetString, CBS_ASN1_OCTETSTRING))
			DMibErrorCryptography("Failed to parse TSTInfo OCTET STRING");

		CBS tstInfo;
		if (!CBS_get_asn1(&tstInfoOctetString, &tstInfo, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("Failed to parse TSTInfo SEQUENCE");

		CTimestampInfo Info;

		uint64_t nVersion = 0;
		if (!CBS_get_asn1_uint64(&tstInfo, &nVersion))
			DMibErrorCryptography("Failed to parse TSTInfo version");
		Info.m_Version = (int32)nVersion;

		CBS policyOIDElement;
		if (!CBS_get_asn1_element(&tstInfo, &policyOIDElement, CBS_ASN1_OBJECT))
			DMibErrorCryptography("Failed to parse TSTInfo policy");
		unsigned char const *pPolicyData = CBS_data(&policyOIDElement);
		ASN1_OBJECT *pPolicyObj = d2i_ASN1_OBJECT(nullptr, &pPolicyData, CBS_len(&policyOIDElement));
		if (pPolicyObj)
		{
			char PolicyBuffer[256];
			OBJ_obj2txt(PolicyBuffer, sizeof(PolicyBuffer), pPolicyObj, 1);
			Info.m_Policy = PolicyBuffer;
			ASN1_OBJECT_free(pPolicyObj);
		}

		CBS messageImprint;
		if (!CBS_get_asn1(&tstInfo, &messageImprint, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("Failed to parse messageImprint");

		CBS hashAlgorithm;
		if (!CBS_get_asn1(&messageImprint, &hashAlgorithm, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("Failed to parse hashAlgorithm");

		CBS hashAlgOIDElement;
		if (!CBS_get_asn1_element(&hashAlgorithm, &hashAlgOIDElement, CBS_ASN1_OBJECT))
			DMibErrorCryptography("Failed to parse hash algorithm OID");

		unsigned char const *pOIDData = CBS_data(&hashAlgOIDElement);
		ASN1_OBJECT *pHashAlgObj = d2i_ASN1_OBJECT(nullptr, &pOIDData, CBS_len(&hashAlgOIDElement));
		if (pHashAlgObj)
		{
			int nNID = OBJ_obj2nid(pHashAlgObj);
			Info.m_MessageImprintAlgorithm = fg_NIDToDigestType(nNID);
			ASN1_OBJECT_free(pHashAlgObj);
		}
		else
			DMibErrorCryptography("Failed to convert OID to ASN1_OBJECT");

		if (Info.m_MessageImprintAlgorithm == EDigestType_None)
			DMibErrorCryptography("Unsupported digest algorithm in timestamp token");

		if (Info.m_MessageImprintAlgorithm == EDigestType_MD5 || Info.m_MessageImprintAlgorithm == EDigestType_SHA1)
			DMibErrorCryptography("Timestamp token uses an insecure digest algorithm");

		CBS hashedMessage;
		if (!CBS_get_asn1(&messageImprint, &hashedMessage, CBS_ASN1_OCTETSTRING))
			DMibErrorCryptography("Failed to parse hashedMessage");
		Info.m_MessageImprint = NContainer::CByteVector(CBS_data(&hashedMessage), CBS_len(&hashedMessage));

		CBS serialNumber;
		if (!CBS_get_asn1(&tstInfo, &serialNumber, CBS_ASN1_INTEGER))
			DMibErrorCryptography("Failed to parse serialNumber");
		Info.m_SerialNumber = NContainer::CByteVector(CBS_data(&serialNumber), CBS_len(&serialNumber));

		CParsedGeneralizedTime ParsedGenTime = fg_ParseGeneralizedTime(&tstInfo);
		Info.m_GenTime = ParsedGenTime.m_Raw;
		Info.m_GenTimeUtc = ParsedGenTime.m_Time;

		if (CBS_len(&tstInfo) > 0 && CBS_peek_asn1_tag(&tstInfo, CBS_ASN1_SEQUENCE))
		{
			CBS accuracy;
			if (!CBS_get_asn1(&tstInfo, &accuracy, CBS_ASN1_SEQUENCE))
				DMibErrorCryptography("Failed to parse accuracy");

			fp64 AccuracySeconds = 0.0;

			if (CBS_len(&accuracy) > 0 && CBS_peek_asn1_tag(&accuracy, CBS_ASN1_INTEGER))
			{
				uint64_t SecondsValue = 0;
				if (!CBS_get_asn1_uint64(&accuracy, &SecondsValue))
					DMibErrorCryptography("Failed to parse accuracy seconds");
				AccuracySeconds += fp64(SecondsValue);
			}

			if (CBS_len(&accuracy) > 0 && CBS_peek_asn1_tag(&accuracy, CBS_ASN1_CONTEXT_SPECIFIC | 0))
			{
				uint64 Millis = fg_ParseImplicitUnsignedInteger(&accuracy, 0, 999, "accuracy.millis");
				AccuracySeconds += fp64(Millis) / 1000.0;
			}

			if (CBS_len(&accuracy) > 0 && CBS_peek_asn1_tag(&accuracy, CBS_ASN1_CONTEXT_SPECIFIC | 1))
			{
				uint64 Micros = fg_ParseImplicitUnsignedInteger(&accuracy, 1, 999, "accuracy.micros");
				AccuracySeconds += fp64(Micros) / 1000000.0;
			}

			if (CBS_len(&accuracy) != 0)
				DMibErrorCryptography("Unsupported extensions in accuracy field");

			Info.m_HasAccuracy = true;
			Info.m_Accuracy = NTime::CTimeSpanConvert::fs_CreateSpanFromSeconds(AccuracySeconds);
		}

		if (CBS_len(&tstInfo) > 0 && CBS_peek_asn1_tag(&tstInfo, CBS_ASN1_BOOLEAN))
		{
			CBS ordering;
			if (CBS_get_asn1(&tstInfo, &ordering, CBS_ASN1_BOOLEAN))
			{
				if (CBS_len(&ordering) == 1)
					Info.m_Ordering = (CBS_data(&ordering)[0] != 0);
			}
		}

		if (CBS_len(&tstInfo) > 0 && CBS_peek_asn1_tag(&tstInfo, CBS_ASN1_INTEGER))
		{
			CBS nonce;
			if (CBS_get_asn1(&tstInfo, &nonce, CBS_ASN1_INTEGER))
				Info.m_Nonce = NContainer::CByteVector(CBS_data(&nonce), CBS_len(&nonce));
		}

		return Info;
	}


	// Verify timestamp token PKCS7 signature
	bool fg_VerifyTimestampSignature
	(
		NContainer::CByteVector const &_TimestampToken
		, CTimestampInfo const &_TimestampInfo
		, CTimestampVerificationOptions const &_Options
	)
	{
		unsigned char const *pData = _TimestampToken.f_GetArray();
		PKCS7 *pPKCS7 = d2i_PKCS7(nullptr, &pData, _TimestampToken.f_GetLen());
		if (!pPKCS7)
			DMibErrorCryptography(NBoringSSL::fg_GetExceptionStr("Failed to parse PKCS7 timestamp token"));
		auto CleanupPKCS7 = g_OnScopeExit / [&]
			{
				PKCS7_free(pPKCS7);
			}
		;

		if (!PKCS7_type_is_signed(pPKCS7))
			DMibErrorCryptography("Timestamp token is not PKCS7 SignedData");

		STACK_OF(X509) *pCerts = sk_X509_new_null();
		if (!pCerts)
			DMibErrorCryptography("Failed to create certificate stack");
		auto CleanupCerts = g_OnScopeExit / [&]
			{
				sk_X509_pop_free(pCerts, X509_free);
			}
		;

		if (pPKCS7->d.sign && pPKCS7->d.sign->cert)
		{
			for (int i = 0; i < sk_X509_num(pPKCS7->d.sign->cert); ++i)
			{
				X509 *pCert = sk_X509_value(pPKCS7->d.sign->cert, i);
				if (!pCert)
					continue;
				X509 *pDup = X509_dup(pCert);
				if (!pDup)
					DMibErrorCryptography("Failed to duplicate certificate from timestamp token");
				sk_X509_push(pCerts, pDup);
			}
		}

		if (sk_X509_num(pCerts) == 0)
			DMibErrorCryptography("No certificates found in timestamp token");

		CBS pkcs7SignerSidCBS;
		CBS_init(&pkcs7SignerSidCBS, pPKCS7->ber_bytes, pPKCS7->ber_len);

		CBS sidContentInfo, sidContentType, sidContent;
		if (!CBS_get_asn1(&pkcs7SignerSidCBS, &sidContentInfo, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&sidContentInfo, &sidContentType, CBS_ASN1_OBJECT) ||
			!CBS_get_asn1(&sidContentInfo, &sidContent, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0))
			DMibErrorCryptography("Failed to parse PKCS7 SignedData for signer certificate selection");

		CBS sidSignedData;
		if (!CBS_get_asn1(&sidContent, &sidSignedData, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("Failed to parse SignedData for signer certificate selection");

		CBS sidVersion, sidDigestAlgorithms, sidEncapContentInfo;
		if (!CBS_get_asn1(&sidSignedData, &sidVersion, CBS_ASN1_INTEGER) ||
			!CBS_get_asn1(&sidSignedData, &sidDigestAlgorithms, CBS_ASN1_SET) ||
			!CBS_get_asn1(&sidSignedData, &sidEncapContentInfo, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("Failed to parse SignedData fields for signer certificate selection");

		if (CBS_len(&sidSignedData) > 0 && CBS_peek_asn1_tag(&sidSignedData, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0))
		{
			CBS certificates;
			CBS_get_asn1(&sidSignedData, &certificates, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0);
		}

		if (CBS_len(&sidSignedData) > 0 && CBS_peek_asn1_tag(&sidSignedData, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1))
		{
			CBS crls;
			CBS_get_asn1(&sidSignedData, &crls, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1);
		}

		CBS sidSignerInfos, sidSignerInfo;
		if (!CBS_get_asn1(&sidSignedData, &sidSignerInfos, CBS_ASN1_SET) || !CBS_get_asn1(&sidSignerInfos, &sidSignerInfo, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("Failed to parse SignerInfo for signer certificate selection");

		CBS sidSignerInfoVersion;
		if (!CBS_get_asn1(&sidSignerInfo, &sidSignerInfoVersion, CBS_ASN1_INTEGER))
			DMibErrorCryptography("Failed to parse SignerInfo version for signer certificate selection");

		CBS selSidElement;
		CBS_ASN1_TAG selSidTag = 0;
		size_t selSidHeaderLen = 0;
		if (!CBS_get_any_asn1_element(&sidSignerInfo, &selSidElement, &selSidTag, &selSidHeaderLen))
			DMibErrorCryptography("Failed to parse SignerInfo sid for signer certificate selection");

		bool bSelSidIsSubjectKeyIdentifier = false;
		NContainer::CByteVector SelSignerSubjectKeyIdentifier;

		if ((selSidTag & ~CBS_ASN1_CONSTRUCTED) == (CBS_ASN1_CONTEXT_SPECIFIC | 0))
		{
			CBS sidValue = selSidElement;
			CBS subjectKeyIdentifier;
			if (!CBS_get_asn1(&sidValue, &subjectKeyIdentifier, selSidTag))
				DMibErrorCryptography("Failed to parse SignerInfo subjectKeyIdentifier for signer certificate selection");

			SelSignerSubjectKeyIdentifier = NContainer::CByteVector(CBS_data(&subjectKeyIdentifier), CBS_len(&subjectKeyIdentifier));
			bSelSidIsSubjectKeyIdentifier = true;
		}

		X509 *pSignerCert = nullptr;
		if (bSelSidIsSubjectKeyIdentifier)
		{
			for (int i = 0; i < sk_X509_num(pCerts); ++i)
			{
				X509 *pCert = sk_X509_value(pCerts, i);
				if (!pCert)
					continue;
				if (fg_SignerSidMatchesCert_SubjectKeyIdentifier(SelSignerSubjectKeyIdentifier, pCert))
				{
					pSignerCert = pCert;
					break;
				}
			}
		}
		else if (selSidTag == CBS_ASN1_SEQUENCE)
		{
			for (int i = 0; i < sk_X509_num(pCerts); ++i)
			{
				X509 *pCert = sk_X509_value(pCerts, i);
				if (!pCert)
					continue;
				if (fg_SignerSidMatchesCert_IssuerAndSerial(selSidElement, pCert))
				{
					pSignerCert = pCert;
					break;
				}
			}
		}
		else
			DMibErrorCryptography("Unsupported SignerInfo sid type");

		if (!pSignerCert)
			DMibErrorCryptography("Failed to locate signer certificate in timestamp token");

		X509_STORE *pStore = X509_STORE_new();
		if (!pStore)
			DMibErrorCryptography("Failed to create X509 store");
		auto CleanupStore = g_OnScopeExit / [&]
			{
				X509_STORE_free(pStore);
			}
		;

		if (_Options.m_TrustedCACertificates.f_IsEmpty())
		{
			CCertificate::fs_GetSystemCertificates(pStore);
		}
		else
		{
			for (auto const &CACertData : _Options.m_TrustedCACertificates)
			{
				X509 *pCACert = fg_LoadCertificate(CACertData);
				auto CleanupCA = g_OnScopeExit / [&]
					{
						// Note: X509_STORE_add_cert increments the reference count, so we still need to free
						X509_free(pCACert);
					}
				;

				ERR_clear_error();
				if (X509_STORE_add_cert(pStore, pCACert) != 1)
				{
					// It's okay if certificate already exists
					unsigned long Err = ERR_peek_last_error();
					if (ERR_GET_REASON(Err) != X509_R_CERT_ALREADY_IN_HASH_TABLE)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to add CA certificate to store"));
				}
			}
		}

		X509_STORE_CTX *pStoreCtx = X509_STORE_CTX_new();
		if (!pStoreCtx)
			DMibErrorCryptography("Failed to create X509 store context");
		auto CleanupStoreCtx = g_OnScopeExit / [&]
			{
				X509_STORE_CTX_free(pStoreCtx);
			}
		;

		STACK_OF(X509) *pChain = sk_X509_new_null();
		if (!pChain)
			DMibErrorCryptography("Failed to create certificate chain stack");
		auto CleanupChain = g_OnScopeExit / [&]
			{
				sk_X509_free(pChain);
			}
		;

		for (int i = 0; i < sk_X509_num(pCerts); ++i)
		{
			X509 *pCert = sk_X509_value(pCerts, i);
			if (!pCert || pCert == pSignerCert)
				continue;
			sk_X509_push(pChain, pCert);
		}

		if (!X509_STORE_CTX_init(pStoreCtx, pStore, pSignerCert, pChain))
			DMibErrorCryptography("Failed to initialize X509 store context");

		X509_VERIFY_PARAM *pVerifyParam = X509_STORE_CTX_get0_param(pStoreCtx);
		if (!pVerifyParam)
			DMibErrorCryptography("Failed to access X509 verification parameters");

		if (_Options.m_bRequireTimestampEKU)
		{
			if (!X509_VERIFY_PARAM_set_purpose(pVerifyParam, X509_PURPOSE_TIMESTAMP_SIGN))
				DMibErrorCryptography("Failed to set timestamp signing purpose for verification");
		}

		if (_Options.m_bCheckCertificateValidityAtGenTime)
		{
			if (!_TimestampInfo.m_GenTimeUtc.f_IsValid())
				DMibErrorCryptography("Timestamp generation time is missing or invalid");
			uint64 UnixSeconds = NTime::CTimeConvert(_TimestampInfo.m_GenTimeUtc).f_UnixSeconds();
			if (UnixSeconds > static_cast<uint64>(std::numeric_limits<time_t>::max()))
				DMibErrorCryptography("Timestamp generation time is outside supported verification range");
			X509_VERIFY_PARAM_set_time(pVerifyParam, static_cast<time_t>(UnixSeconds));
		}

		int nVerifyResult = X509_verify_cert(pStoreCtx);
		if (nVerifyResult != 1)
		{
			int nError = X509_STORE_CTX_get_error(pStoreCtx);
			NStr::CStr ErrorStr = X509_verify_cert_error_string(nError);
			DMibErrorCryptography("Timestamp certificate chain verification failed: {}"_f << ErrorStr);
		}

		CBS pkcs7CBS;
		CBS_init(&pkcs7CBS, pPKCS7->ber_bytes, pPKCS7->ber_len);

		CBS contentInfo, contentType, content;
		if (!CBS_get_asn1(&pkcs7CBS, &contentInfo, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&contentInfo, &contentType, CBS_ASN1_OBJECT) ||
			!CBS_get_asn1(&contentInfo, &content, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0))
			DMibErrorCryptography("Failed to parse PKCS7 SignedData for signature verification");

		CBS signedData;
		if (!CBS_get_asn1(&content, &signedData, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("Failed to parse SignedData SEQUENCE");

		CBS version, digestAlgorithms, encapContentInfo;
		if (!CBS_get_asn1(&signedData, &version, CBS_ASN1_INTEGER) ||
			!CBS_get_asn1(&signedData, &digestAlgorithms, CBS_ASN1_SET) ||
			!CBS_get_asn1(&signedData, &encapContentInfo, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("Failed to parse SignedData fields");

		CBS encapContentType, tstInfoTagged, tstInfoOctetString;
		if (!CBS_get_asn1(&encapContentInfo, &encapContentType, CBS_ASN1_OBJECT) ||
			!CBS_get_asn1(&encapContentInfo, &tstInfoTagged, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
			!CBS_get_asn1(&tstInfoTagged, &tstInfoOctetString, CBS_ASN1_OCTETSTRING))
			DMibErrorCryptography("Failed to extract encapsulated content for signature verification");

		CBS contentToSign = tstInfoOctetString;

		if (CBS_len(&signedData) > 0 && CBS_peek_asn1_tag(&signedData, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0))
		{
			CBS certificates;
			CBS_get_asn1(&signedData, &certificates, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0);
		}

		if (CBS_len(&signedData) > 0 && CBS_peek_asn1_tag(&signedData, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1))
		{
			CBS crls;
			CBS_get_asn1(&signedData, &crls, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1);
		}

		CBS signerInfos, signerInfo;
		if (!CBS_get_asn1(&signedData, &signerInfos, CBS_ASN1_SET) ||
			!CBS_get_asn1(&signerInfos, &signerInfo, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("Failed to parse SignerInfo");

		CBS siVersion;
		if (!CBS_get_asn1(&signerInfo, &siVersion, CBS_ASN1_INTEGER))
			DMibErrorCryptography("Failed to parse SignerInfo version");

		CBS sidElement;
		CBS_ASN1_TAG sidTag = 0;
		size_t sidHeaderLen = 0;
		bool bSidIsSubjectKeyIdentifier = false;
		NContainer::CByteVector SignerSubjectKeyIdentifier;
		if (!CBS_get_any_asn1_element(&signerInfo, &sidElement, &sidTag, &sidHeaderLen))
			DMibErrorCryptography("Failed to parse SignerInfo sid");

		if (sidTag == CBS_ASN1_SEQUENCE)
		{
			fg_VerifyIssuerAndSerial(sidElement, pSignerCert, "SignerInfo.sid");
		}
		else if ((sidTag & ~CBS_ASN1_CONSTRUCTED) == (CBS_ASN1_CONTEXT_SPECIFIC | 0))
		{
			CBS sidValue = sidElement;
			CBS subjectKeyIdentifier;
			if (!CBS_get_asn1(&sidValue, &subjectKeyIdentifier, sidTag))
				DMibErrorCryptography("Failed to parse SignerInfo subjectKeyIdentifier");

			SignerSubjectKeyIdentifier = NContainer::CByteVector(CBS_data(&subjectKeyIdentifier), CBS_len(&subjectKeyIdentifier));
			bSidIsSubjectKeyIdentifier = true;
		}
		else
			DMibErrorCryptography("Unsupported SignerInfo sid type");

		CBS siDigestAlgorithm;
		if (!CBS_get_asn1(&signerInfo, &siDigestAlgorithm, CBS_ASN1_SEQUENCE))
			DMibErrorCryptography("Failed to parse SignerInfo digestAlgorithm");

		CBS signedAttrsElement;
		bool bHasSignedAttrs = false;
		if (CBS_len(&signerInfo) > 0 && CBS_peek_asn1_tag(&signerInfo, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0))
		{
			if (!CBS_get_asn1_element(&signerInfo, &signedAttrsElement, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0))
				DMibErrorCryptography("Failed to parse signedAttrs");
			bHasSignedAttrs = true;
		}

		CBS signatureAlgorithm, signatureValue;
		if (!CBS_get_asn1(&signerInfo, &signatureAlgorithm, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&signerInfo, &signatureValue, CBS_ASN1_OCTETSTRING))
			DMibErrorCryptography("Failed to parse signature value");

		EVP_PKEY *pPublicKey = X509_get_pubkey(pSignerCert);
		if (!pPublicKey)
			DMibErrorCryptography("Failed to get public key from signer certificate");
		auto CleanupPublicKey = g_OnScopeExit / [&]
			{
				EVP_PKEY_free(pPublicKey);
			}
		;

		CBS siDigestAlgOID;
		if (!CBS_get_asn1_element(&siDigestAlgorithm, &siDigestAlgOID, CBS_ASN1_OBJECT))
			DMibErrorCryptography("Failed to parse digest algorithm OID");

		unsigned char const *pDigestOIDData = CBS_data(&siDigestAlgOID);
		ASN1_OBJECT *pDigestAlgObj = d2i_ASN1_OBJECT(nullptr, &pDigestOIDData, CBS_len(&siDigestAlgOID));
		if (!pDigestAlgObj)
			DMibErrorCryptography("Failed to convert digest algorithm OID");
		auto CleanupDigestAlg = g_OnScopeExit / [&]
			{
				ASN1_OBJECT_free(pDigestAlgObj);
			}
		;

		int nDigestNID = OBJ_obj2nid(pDigestAlgObj);
		EVP_MD const *pDigest = EVP_get_digestbynid(nDigestNID);
		if (!pDigest)
			DMibErrorCryptography("Unsupported digest algorithm in SignerInfo");

		NContainer::CByteVector ContentDigest = fg_CreateDigest(pDigest, contentToSign);

		int nSignerDerLen = i2d_X509(pSignerCert, nullptr);
		if (nSignerDerLen <= 0)
			DMibErrorCryptography("Failed to encode signer certificate");
		NContainer::CByteVector SignerCertDer;
		SignerCertDer.f_SetLen(nSignerDerLen);
		unsigned char *pDerCursor = SignerCertDer.f_GetArray();
		if (i2d_X509(pSignerCert, &pDerCursor) != nSignerDerLen)
			DMibErrorCryptography("Failed to encode signer certificate");

		if (bSidIsSubjectKeyIdentifier)
		{
			if (!fg_SignerSidMatchesCert_SubjectKeyIdentifier(SignerSubjectKeyIdentifier, pSignerCert))
				DMibErrorCryptography("SignerInfo subjectKeyIdentifier does not match signer certificate");
		}

		bool bFoundContentType = false;
		bool bFoundMessageDigest = false;
		bool bFoundEssCertId = false;

		if (bHasSignedAttrs)
		{
			CBS signedAttrsTagged = signedAttrsElement;
			if (!CBS_get_asn1(&signedAttrsTagged, &signedAttrsTagged, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0))
				DMibErrorCryptography("Failed to parse signedAttrs contents");

			CBS signedAttrsSet = signedAttrsTagged;

			auto ValidateSigningCertificate = [&](CBS _AttrValues, bool _bV2)
			{
				CBS attrValuesCopy = _AttrValues;
				CBS signingCertificate;
				if (!CBS_get_asn1(&attrValuesCopy, &signingCertificate, CBS_ASN1_SEQUENCE))
					DMibErrorCryptography("Failed to parse SigningCertificate attribute");
				if (CBS_len(&attrValuesCopy) != 0)
					DMibErrorCryptography("Unexpected extra data in SigningCertificate attribute");

				CBS certsSequence;
				if (!CBS_get_asn1(&signingCertificate, &certsSequence, CBS_ASN1_SEQUENCE))
					DMibErrorCryptography("Failed to parse SigningCertificate certs sequence");
				if (CBS_len(&certsSequence) == 0)
					DMibErrorCryptography("SigningCertificate must contain at least one cert");

				CBS essCert;
				if (!CBS_get_asn1(&certsSequence, &essCert, CBS_ASN1_SEQUENCE))
					DMibErrorCryptography("Failed to parse ESSCertID structure");

				EVP_MD const *pCertHashDigest = _bV2 ? EVP_sha256() : EVP_sha1();

				if (_bV2 && CBS_len(&essCert) > 0 && CBS_peek_asn1_tag(&essCert, CBS_ASN1_SEQUENCE))
				{
					CBS hashAlgorithm;
					if (!CBS_get_asn1(&essCert, &hashAlgorithm, CBS_ASN1_SEQUENCE))
						DMibErrorCryptography("Failed to parse SigningCertificateV2 hash algorithm");
					CBS hashAlgOidElement;
					if (!CBS_get_asn1_element(&hashAlgorithm, &hashAlgOidElement, CBS_ASN1_OBJECT))
						DMibErrorCryptography("Failed to parse SigningCertificateV2 hash algorithm OID");
					unsigned char const *pAlgData = CBS_data(&hashAlgOidElement);
					ASN1_OBJECT *pAlgObj = d2i_ASN1_OBJECT(nullptr, &pAlgData, CBS_len(&hashAlgOidElement));
					if (!pAlgObj)
						DMibErrorCryptography("Failed to decode SigningCertificateV2 hash algorithm OID");
					auto CleanupAlgObj = g_OnScopeExit / [&]
					{
						ASN1_OBJECT_free(pAlgObj);
					}
					;
					int nAlgNid = OBJ_obj2nid(pAlgObj);
					EVP_MD const *pResolvedDigest = EVP_get_digestbynid(nAlgNid);
					if (!pResolvedDigest)
						DMibErrorCryptography("Unsupported SigningCertificateV2 hash algorithm");
					pCertHashDigest = pResolvedDigest;

					if (CBS_len(&hashAlgorithm) > 0)
					{
						CBS parameters;
						if (!CBS_get_asn1(&hashAlgorithm, &parameters, CBS_ASN1_NULL))
							DMibErrorCryptography("Unsupported SigningCertificateV2 hash algorithm parameters");
						if (CBS_len(&hashAlgorithm) != 0)
							DMibErrorCryptography("Unsupported SigningCertificateV2 hash algorithm parameters");
					}
				}

				CBS certHash;
				if (!CBS_get_asn1(&essCert, &certHash, CBS_ASN1_OCTETSTRING))
					DMibErrorCryptography("Failed to parse SigningCertificate certHash");
				NContainer::CByteVector ExpectedDigest = fg_CreateDigest(pCertHashDigest, SignerCertDer.f_GetArray(), SignerCertDer.f_GetLen());
				if (CBS_len(&certHash) != ExpectedDigest.f_GetLen() ||
					memcmp(CBS_data(&certHash), ExpectedDigest.f_GetArray(), ExpectedDigest.f_GetLen()) != 0)
					DMibErrorCryptography("SigningCertificate certHash does not match signer certificate");

				if (CBS_len(&essCert) > 0 && CBS_peek_asn1_tag(&essCert, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0))
				{
					CBS issuerSerial;
					if (!CBS_get_asn1(&essCert, &issuerSerial, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0))
						DMibErrorCryptography("Failed to parse SigningCertificate issuerSerial");
				}

				if (CBS_len(&essCert) != 0)
					DMibErrorCryptography("Unexpected data in SigningCertificate attribute");
			};

			while (CBS_len(&signedAttrsSet) > 0)
			{
			CBS attribute;
			if (!CBS_get_asn1(&signedAttrsSet, &attribute, CBS_ASN1_SEQUENCE))
				DMibErrorCryptography("Failed to parse attribute sequence");

			CBS attrTypeElement;
			CBS_ASN1_TAG attrTypeTag;
			size_t attrTypeHeaderLen = 0;
			if (!CBS_get_any_asn1_element(&attribute, &attrTypeElement, &attrTypeTag, &attrTypeHeaderLen) || attrTypeTag != CBS_ASN1_OBJECT)
				DMibErrorCryptography("Failed to parse attribute type");

			CBS attrValues;
			if (!CBS_get_asn1(&attribute, &attrValues, CBS_ASN1_SET))
				DMibErrorCryptography("Failed to parse attribute contents");

			unsigned char const *pAttrOid = CBS_data(&attrTypeElement);
			ASN1_OBJECT *pAttrObj = d2i_ASN1_OBJECT(nullptr, &pAttrOid, CBS_len(&attrTypeElement));
			if (!pAttrObj)
				DMibErrorCryptography("Failed to decode attribute OID");
			auto CleanupAttrObj = g_OnScopeExit / [&]
			{
						ASN1_OBJECT_free(pAttrObj);
					}
				;

				int nAttrNid = OBJ_obj2nid(pAttrObj);

				COidMatcher AttrOidMatcher(nAttrNid, pAttrObj);

				if (AttrOidMatcher.f_Equals(mc_NidPkcs9ContentType, mc_Oid_Pkcs9ContentType))
				{
				CBS attrValuesCopy = attrValues;
				CBS contentTypeValueElement;
				CBS_ASN1_TAG contentTypeTag;
				size_t contentTypeHeaderLen = 0;
				if (!CBS_get_any_asn1_element(&attrValuesCopy, &contentTypeValueElement, &contentTypeTag, &contentTypeHeaderLen) || contentTypeTag != CBS_ASN1_OBJECT)
					DMibErrorCryptography("Failed to parse contentType attribute");
				if (CBS_len(&attrValuesCopy) != 0)
					DMibErrorCryptography("Unexpected data in contentType attribute");

				unsigned char const *pContentOid = CBS_data(&contentTypeValueElement);
				ASN1_OBJECT *pContentObj = d2i_ASN1_OBJECT(nullptr, &pContentOid, CBS_len(&contentTypeValueElement));
					if (!pContentObj)
						DMibErrorCryptography("Failed to decode contentType value");
					auto CleanupContentObj = g_OnScopeExit / [&]
					{
							ASN1_OBJECT_free(pContentObj);
					}
					;

					int nContentNid = OBJ_obj2nid(pContentObj);
					COidMatcher ContentMatcher(nContentNid, pContentObj);
					if (!ContentMatcher.f_Equals(mc_NidTstInfo, mc_Oid_TSTInfo))
						DMibErrorCryptography("SignerInfo contentType attribute does not reference TSTInfo");

					bFoundContentType = true;
				}
				else if (AttrOidMatcher.f_Equals(mc_NidPkcs9MessageDigest, mc_Oid_Pkcs9MessageDigest))
				{
					CBS attrValuesCopy = attrValues;
					CBS digestValue;
					if (!CBS_get_asn1(&attrValuesCopy, &digestValue, CBS_ASN1_OCTETSTRING))
					{
						DMibErrorCryptography("Failed to parse messageDigest attribute");
					}
					if (CBS_len(&attrValuesCopy) != 0)
					{
						DMibErrorCryptography("Unexpected data in messageDigest attribute");
					}

					if (CBS_len(&digestValue) != ContentDigest.f_GetLen() ||
						memcmp(CBS_data(&digestValue), ContentDigest.f_GetArray(), ContentDigest.f_GetLen()) != 0)
					{
						DMibErrorCryptography("SignerInfo messageDigest attribute does not match TSTInfo content");
					}

					bFoundMessageDigest = true;
				}
				else if (AttrOidMatcher.f_Equals(mc_NidSigningCertificate, mc_Oid_SigningCertificate))
				{
					ValidateSigningCertificate(attrValues, false);
					bFoundEssCertId = true;
				}
				else if (AttrOidMatcher.f_Equals(mc_NidSigningCertificateV2, mc_Oid_SigningCertificateV2))
				{
					ValidateSigningCertificate(attrValues, true);
					bFoundEssCertId = true;
				}
			}

			if (_Options.m_bRequireContentTypeAttr && !bFoundContentType)
				DMibErrorCryptography("SignerInfo missing required contentType attribute");
			if (_Options.m_bRequireMessageDigestAttr && !bFoundMessageDigest)
				DMibErrorCryptography("SignerInfo missing required messageDigest attribute");
			if (_Options.m_bRequireEssCertIdMatch && !bFoundEssCertId)
				DMibErrorCryptography("SignerInfo missing required ESSCertID attribute");
		}
		else if (_Options.m_bRequireSignedAttributes)
			DMibErrorCryptography("Timestamp token is missing signed attributes");

		EVP_MD_CTX *pMDCtx = EVP_MD_CTX_create();
		if (!pMDCtx)
			DMibErrorCryptography("Failed to create digest context");
		auto CleanupMDCtx = g_OnScopeExit / [&]
			{
				EVP_MD_CTX_destroy(pMDCtx);
			}
		;

		if (EVP_DigestVerifyInit(pMDCtx, nullptr, pDigest, nullptr, pPublicKey) != 1)
			DMibErrorCryptography(NBoringSSL::fg_GetExceptionStr("EVP_DigestVerifyInit failed"));

		if (bHasSignedAttrs)
		{
			NContainer::CByteVector SignedAttrsData(CBS_data(&signedAttrsElement), CBS_len(&signedAttrsElement));
			if (SignedAttrsData.f_IsEmpty())
				DMibErrorCryptography("Invalid signedAttrs encoding");
			SignedAttrsData[0] = 0x31;
			if (EVP_DigestVerifyUpdate(pMDCtx, SignedAttrsData.f_GetArray(), SignedAttrsData.f_GetLen()) != 1)
				DMibErrorCryptography(NBoringSSL::fg_GetExceptionStr("EVP_DigestVerifyUpdate failed"));
		}
		else
		{
			if (EVP_DigestVerifyUpdate(pMDCtx, CBS_data(&contentToSign), CBS_len(&contentToSign)) != 1)
				DMibErrorCryptography(NBoringSSL::fg_GetExceptionStr("EVP_DigestVerifyUpdate failed"));
		}

		int nSigVerifyResult = EVP_DigestVerifyFinal(pMDCtx, CBS_data(&signatureValue), CBS_len(&signatureValue));
		if (nSigVerifyResult != 1)
		{
			if (nSigVerifyResult == 0)
				DMibErrorCryptography("PKCS7 signature verification failed - signature mismatch");
			else
				DMibErrorCryptography(NBoringSSL::fg_GetExceptionStr("PKCS7 signature verification failed"));
		}

		return true;
	}

	// Validate that timestamp message imprint matches expected digest
	bool fg_ValidateTimestampImprint
		(
			CTimestampInfo const &_TimestampInfo
			, NContainer::CByteVector const &_ExpectedDigest
			, EDigestType _ExpectedDigestType
		)
	{
		// Check digest type matches
		if (_TimestampInfo.m_MessageImprintAlgorithm != _ExpectedDigestType)
		{
			CStr ErrorMsg = "Timestamp digest algorithm mismatch: expected {}, got {}"_f
				<< (int32)_ExpectedDigestType
				<< (int32)_TimestampInfo.m_MessageImprintAlgorithm;
			DMibErrorCryptography(ErrorMsg);
		}

		// Check digest value matches
		if (_TimestampInfo.m_MessageImprint.f_GetLen() != _ExpectedDigest.f_GetLen())
		{
			CStr ErrorMsg = "Timestamp digest length mismatch: expected {}, got {}"_f
				<< _ExpectedDigest.f_GetLen()
				<< _TimestampInfo.m_MessageImprint.f_GetLen();
			DMibErrorCryptography(ErrorMsg);
		}

		if (memcmp
			(
				_TimestampInfo.m_MessageImprint.f_GetArray()
				, _ExpectedDigest.f_GetArray()
				, _ExpectedDigest.f_GetLen()
			) != 0)
		{
			DMibErrorCryptography("Timestamp message imprint does not match expected digest");
		}

		return true;
	}


	// Complete timestamp verification
	CTimestampInfo fg_VerifyTimestamp
		(
			NContainer::CByteVector const &_TimestampToken
			, NContainer::CByteVector const &_ExpectedDigest
			, EDigestType _ExpectedDigestType
			, CTimestampVerificationOptions const &_Options
		)
	{
		CTimestampInfo Info = fg_ParseTimestampToken(_TimestampToken);

		fg_VerifyTimestampSignature(_TimestampToken, Info, _Options);

		fg_ValidateTimestampImprint(Info, _ExpectedDigest, _ExpectedDigestType);

		if (_Options.f_HasNonce())
		{
			if (Info.m_Nonce.f_IsEmpty())
				DMibErrorCryptography("Timestamp token missing nonce");
			if (Info.m_Nonce.f_GetLen() != _Options.m_ExpectedNonce.f_GetLen() ||
				memcmp(Info.m_Nonce.f_GetArray(), _Options.m_ExpectedNonce.f_GetArray(), _Options.m_ExpectedNonce.f_GetLen()) != 0)
				DMibErrorCryptography("Timestamp nonce mismatch");
		}

		if (_Options.f_HasPolicy())
		{
			if (Info.m_Policy != _Options.m_ExpectedPolicy)
				DMibErrorCryptography("Timestamp policy mismatch");
		}

		if (_Options.f_HasMinimumTime())
		{
			if (!Info.m_GenTimeUtc.f_IsValid())
				DMibErrorCryptography("Timestamp generation time is missing");
			if (Info.m_GenTimeUtc < _Options.m_MinimumGenTime)
				DMibErrorCryptography("Timestamp generation time is earlier than allowed minimum");
		}

		if (_Options.f_HasMaximumTime())
		{
			if (!Info.m_GenTimeUtc.f_IsValid())
				DMibErrorCryptography("Timestamp generation time is missing");
			if (Info.m_GenTimeUtc > _Options.m_MaximumGenTime)
				DMibErrorCryptography("Timestamp generation time is later than allowed maximum");
		}

		if (_Options.f_HasAccuracyLimit())
		{
			if (!Info.m_HasAccuracy)
				DMibErrorCryptography("Timestamp accuracy is not provided");
			if (Info.m_Accuracy > _Options.m_MaxAccuracy)
				DMibErrorCryptography("Timestamp accuracy exceeds allowed maximum");
		}

		return Info;
	}

}
