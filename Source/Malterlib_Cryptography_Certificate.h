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

	// Peer-role restriction for fs_VerifyCertificateChain. A leaf certificate that carries no extended
	// key usage extension satisfies any purpose; one that does carry an extended key usage must include
	// the matching usage. The leaf is checked directly (not only through the store context, which skips
	// a leaf that is its own trust anchor), and because both roles authenticate by producing signatures,
	// a key usage extension on the leaf must include digitalSignature
	enum EVerificationPurpose
	{
		EVerificationPurpose_Any = 0 // No extended-key-usage restriction
		, EVerificationPurpose_ServerAuth // Leaf must be usable as a TLS server (serverAuth) and able to sign
		, EVerificationPurpose_ClientAuth // Leaf must be usable as a TLS client (clientAuth) and able to sign
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
		// _PathLength >= 0 adds a basicConstraints pathlen for a CA (0 forbids any intermediate CA below
		// this one, so it may only issue end-entity certificates); -1 omits the constraint
		void f_AddExtension_BasicConstraints(bool _bCA, bool _bCritical = true, int32 _PathLength = -1);
		void f_AddExtension_KeyUsage(EKeyUsage _KeyUsage, bool _bCritical = true);
		void f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage _KeyUsage, bool _bCritical = true);
		void f_MakeCA();

		NStr::CStr m_CommonName; // CN
		NContainer::TCMap<NStr::CStr, NStr::CStr> m_RelativeDistinguishedNames;
		NContainer::TCVector<NStr::CStr> m_Hostnames;
		NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> m_Extensions;
		CPublicKeySetting m_KeySetting;
	};

	// Signer-enforced leaf role for fs_SignClientCertificate. A signer that accepts an untrusted
	// certificate request cannot let the requester decide whether the issued certificate is a CA or
	// which authentication role it carries: a wholesale copy of the request extensions would let a
	// requester stamp basicConstraints CA:TRUE (minting an intermediate that still chains to the
	// pinned CA) or the opposite authentication role. When the role is not Unrestricted the signer
	// drops the requester's copy of basicConstraints, keyUsage, and extendedKeyUsage and stamps a
	// non-CA leaf constrained to the selected role instead. Unrestricted keeps the historical
	// behavior of copying every request extension verbatim, which callers minting their own CAs and
	// role-scoped certificates through a trusted request rely on
	enum ECertificateLeafRole
	{
		ECertificateLeafRole_Unrestricted = 0
		, ECertificateLeafRole_ServerAuth // Non-CA leaf constrained to serverAuth
		, ECertificateLeafRole_ClientAuth // Non-CA leaf constrained to clientAuth
	};

	struct CCertificateSignOptions
	{
		void f_AddExtension_SubjectKeyIdentifier(bool _bCritical = false);
		void f_AddExtension_AuthorityKeyIdentifier(bool _bCritical = false);

		EDigestType m_Digest = EDigestType_Automatic;
		int32 m_Serial = 1;
		int32 m_Days = 365;
		NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> m_Extensions;
		ECertificateLeafRole m_LeafRole = ECertificateLeafRole_Unrestricted;

		// Whitelist of public key types the signer will accept in the certificate request. When
		// non-empty, the request's key must match one entry or signing fails: an EC entry requires
		// that exact curve, and an RSA entry requires an RSA key whose size is at least the entry's
		// m_KeyLength (a minimum, not an exact size). Empty accepts any key. This is independent of
		// m_LeafRole; a caller signing untrusted requests uses it to pin the acceptable key policy (for
		// example the distributed actors accept only secp521r1)
		NContainer::TCVector<CPublicKeySetting> m_AllowedKeyTypes;

		// Whitelist of digests the certificate request's own signature may use. When non-empty, a
		// request whose self-signature uses a digest not listed here is rejected, so the proof of
		// possession cannot rest on a weak (forgeable) digest. Empty accepts any digest. Independent of
		// m_LeafRole; the distributed actors list only SHA-512 (the automatic digest for their
		// secp521r1 keys)
		NContainer::TCVector<EDigestType> m_AllowedRequestDigests;

		// When non-empty, the signer sets the issued certificate's subject to a single common name with
		// this value instead of copying the subject from the request. A certificate authority signing an
		// untrusted request uses this so the requester cannot place arbitrary or misleading content in
		// the subject; the distributed actors do not authenticate on the subject (identity is the
		// MalterlibHostID extension), so the common name is purely descriptive
		NStr::CStr m_OverrideSubjectCommonName;

		// Whitelist of certificate-request extensions the signer will copy into the issued
		// certificate, given as dotted numeric OIDs (for example "2.5.29.17" for subjectAltName). When
		// non-empty, a request extension is copied only when its OID is listed and every other request
		// extension is dropped; a certificate authority signing an untrusted request uses this so a
		// requester cannot smuggle in identity, constraint, or usage extensions the signer did not
		// vet. Empty keeps the historical behavior of copying every request extension verbatim
		NContainer::TCVector<NStr::CStr> m_AllowedRequestExtensions;
	};

	// Verification-side counterpart of the CCertificateSignOptions whitelists: restricts the
	// presented leaf certificate to the key types and signature digests the caller's protocol
	// actually issues. An empty vector leaves that axis unrestricted
	struct CCertificateVerifyOptions
	{
		// Allowed leaf public key types; an RSA entry's key length is a minimum
		NContainer::TCVector<CPublicKeySetting> m_AllowedLeafKeyTypes;

		// Allowed digests for the leaf certificate's signature algorithm
		NContainer::TCVector<EDigestType> m_AllowedSignatureDigests;
	};

	struct CCertificate
	{
		static NStr::CStr fs_GetCertificateName(NContainer::CByteVector const &_CertificateData);
		static NStr::CStr fs_GetCertificateDistinguishedName_RFC2253(NContainer::CByteVector const &_CertificateData);
		static NStr::CStr fs_GetIssuerName(NContainer::CByteVector const &_CertificateData);
		static bool fs_IsRoot(NContainer::CByteVector const &_CertificateData);

		// The digest the certificate's own signature was made with; EDigestType_None for a
		// signature whose digest this module does not name. A self-signed authority's is the
		// digest it signs its leaves with when the signer leaves the digest automatic
		static EDigestType fs_GetSignatureDigestType(NContainer::CByteVector const &_CertificateData);
		static NStr::CStr fs_GetCertificateFingerprint(NContainer::CByteVector const &_CertificateData);
		static NContainer::CByteVector fs_GetCertificateFingerprintData(NContainer::CByteVector const &_CertificateData, EDigestType _Digest = EDigestType_SHA256);
		static NContainer::CByteVector fs_GetCertificateTLSServerEndPointData(NContainer::CByteVector const &_CertificateData);
		static NContainer::TCVector<NStr::CStr> fs_GetCertificateHostnames(NContainer::CByteVector const &_CertificateData, bool _bCheckCommonName = true);
		static NContainer::TCVector<NStr::CStr> fs_GetSortedHostnames(NContainer::TCVector<NStr::CStr> const &_Unsorted);
		static NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> fs_GetCertificateExtensions(NContainer::CByteVector const &_CertificateData);
		static NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> fs_GetCertificateRequestExtensions(NContainer::CByteVector const &_CertificateData);

		// DER SubjectPublicKeyInfo, the format CPublicCrypto::fs_VerifySignature accepts as key data
		static NContainer::CSecureByteVector fs_GetCertificatePublicKey(NContainer::CByteVector const &_CertificateData);

		// An explicitly supplied CA certificate is a trust anchor even when it is not a self-signed
		// root (a CA-issued leaf or intermediate pinned directly terminates the path). System-store
		// verification does not get this partial-chain treatment, because that store also carries
		// chain-building intermediates that are not independently trusted
		static bool fs_VerifyCertificateChain
			(
				NContainer::TCVector<NContainer::CByteVector> const &_CertificateChain // Leaf first, any intermediates after
				, NContainer::CByteVector const &_CACertificateData
				, bool _bUseSystemStoreIfNoCA
				, EVerificationPurpose _RequiredPurpose // Reject a leaf whose key usages exclude this role; Any disables the check
				, CCertificateVerifyOptions const &_VerifyOptions
				, NContainer::TCVector<NContainer::CByteVector> *o_pVerifiedChain // If non-null, receives the verified path (leaf first) on success; may differ from _CertificateChain
				, NStr::CStr &o_Error
			)
		;

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

		// True when every certificate fs_GetSystemCertificates loads is a trust anchor by platform
		// policy, so chain verification may stop at any store match (X509_V_FLAG_PARTIAL_CHAIN)
		// instead of requiring a self-signed root. False where the store also carries
		// chain-building intermediates that are not independently trusted
		static bool fs_SystemStoreCertificatesAreAnchors();

		static NContainer::CByteVector fs_ConvertToDer_CertificateSigningRequest(NContainer::CByteVector const &_Pem);
		static NContainer::CByteVector fs_ConvertToDer_Certificate(NContainer::CByteVector const &_Pem);
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
