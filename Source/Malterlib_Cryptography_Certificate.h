// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "Malterlib_Cryptography_Exception.h"
#include "Malterlib_Cryptography_PublicCrypto.h"

extern "C"
{
	typedef struct x509_store_st X509_STORE;
}

namespace NMib::NCryptography
{
	enum EKeyUsage
	{
		EKeyUsage_None = 0
		, EKeyUsage_DigitalSignature = DMibBit(0)
		, EKeyUsage_NonRepudiation = DMibBit(1)
		, EKeyUsage_KeyEncipherment = DMibBit(2)
		, EKeyUsage_DataEncipherment = DMibBit(3)
		, EKeyUsage_KeyAgreement = DMibBit(4)
		, EKeyUsage_CertificateSign = DMibBit(5)
		, EKeyUsage_CRLSign = DMibBit(6)
		, EKeyUsage_EncipherOnly = DMibBit(7)
		, EKeyUsage_DecipherOnly = DMibBit(8)
	};

	enum EExtendedKeyUsage
	{
		EExtendedKeyUsage_None = 0
		, EExtendedKeyUsage_ServerAuth = DMibBit(0)
		, EExtendedKeyUsage_ClientAuth = DMibBit(1)
		, EExtendedKeyUsage_CodeSigning = DMibBit(2)
		, EExtendedKeyUsage_EmailProtection = DMibBit(3)
		, EExtendedKeyUsage_Timestamping = DMibBit(4)
	};

	struct CCertificateExtension
	{
		auto operator <=> (CCertificateExtension const &_Right) const noexcept = default;

		template <typename tf_CFormatInto>
		void f_Format(tf_CFormatInto &o_FormatInto) const
		{
			o_FormatInto += typename tf_CFormatInto::CFormat("{}{}") << m_Value << (m_bCritical ? " - critical" : "");
		}

		NStr::CStr m_Value;
		bool m_bCritical = false;
	};

	struct CCertificateOptions
	{
		void f_AddExtension_BasicConstraints(bool _bCA, bool _bCritical = true);
		void f_AddExtension_KeyUsage(EKeyUsage _KeyUsage, bool _bCritical = true);
		void f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage _KeyUsage, bool _bCritical = true);
		void f_MakeCA();

		NStr::CStr m_CommonName; // CN
		NContainer::TCMap<NStr::CStr, NStr::CStr> m_RelativeDistinguishedNames;
		NContainer::TCVector<NStr::CStr> m_Hostnames;
		NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> m_Extensions;
		CPublicKeySetting m_KeySetting;
	};

	struct CCertificateSignOptions
	{
		void f_AddExtension_SubjectKeyIdentifier(bool _bCritical = false);
		void f_AddExtension_AuthorityKeyIdentifier(bool _bCritical = false);

		EDigestType m_Digest = EDigestType_Automatic;
		int32 m_Serial = 1;
		int32 m_Days = 365;
		NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> m_Extensions;
	};

	struct CCertificate
	{
		static NStr::CStr fs_GetCertificateName(NContainer::CByteVector const &_CertificateData);
		static NStr::CStr fs_GetCertificateDistinguishedName_RFC2253(NContainer::CByteVector const &_CertificateData);
		static NStr::CStr fs_GetIssuerName(NContainer::CByteVector const &_CertificateData);
		static bool fs_IsRoot(NContainer::CByteVector const &_CertificateData);
		static NStr::CStr fs_GetCertificateFingerprint(NContainer::CByteVector const &_CertificateData);
		static NContainer::TCVector<NStr::CStr> fs_GetCertificateHostnames(NContainer::CByteVector const &_CertificateData, bool _bCheckCommonName = true);
		static NContainer::TCVector<NStr::CStr> fs_GetSortedHostnames(NContainer::TCVector<NStr::CStr> const &_Unsorted);
		static NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> fs_GetCertificateExtensions(NContainer::CByteVector const &_CertificateData);
		static NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> fs_GetCertificateRequestExtensions(NContainer::CByteVector const &_CertificateData);

		static NStr::CStr fs_GetCertificateHostnamesStr(NContainer::CByteVector const &_CertificateData);
		static NTime::CTime fs_GetCertificateExpirationTime(NContainer::CByteVector const &_CertificateData);
		static NTime::CTime fs_GetCertificateIssueTime(NContainer::CByteVector const &_CertificateData);
		static NStr::CStr fs_GetCertificateDescription(NContainer::CByteVector const &_CertificateData);
		static NStr::CStr fs_GetCertificateInformation(NContainer::CByteVector const &_CertificateData);

		static void fs_RegisterExtension(NStr::CStr const &_OID, NStr::CStr const &_ShortName, NStr::CStr const &_LongName);

		static void fs_GenerateSelfSignedCertAndKey
			(
				CCertificateOptions const &_Options
				, NContainer::CByteVector &o_CertData
				, NContainer::CSecureByteVector &o_KeyData
				, CCertificateSignOptions const &_SignOptions = {}
			)
		;

		static void fs_GenerateClientCertificateRequest
			(
				CCertificateOptions const &_Options
				, NContainer::CByteVector &o_CertRequestData
				, NContainer::CSecureByteVector &o_KeyData
				, EDigestType _Digest = EDigestType_Automatic
			)
		;

		static void fs_SignClientCertificate
			(
				NContainer::CByteVector const &_CACertificate
				, NContainer::CSecureByteVector const &_CAKey
				, NContainer::CByteVector const &_CertRequestData
				, NContainer::CByteVector &o_SignedCertificateData
				, CCertificateSignOptions const &_SignOptions = {}
			)
		;

		static void fs_VerifyCertificateRequestSameKeyAsCertificate(NContainer::CByteVector const &_CertRequestData, NContainer::CByteVector const &_CertData);

		static void fs_GetSystemCertificates(X509_STORE *_pCertificateStoreStore);

		static NContainer::CByteVector fs_ConvertToDer_CertificateSigningRequest(NContainer::CByteVector const &_Pem);
		static NContainer::CByteVector fs_ConvertToDer_Certificate(NContainer::CByteVector const &_Pem);
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
