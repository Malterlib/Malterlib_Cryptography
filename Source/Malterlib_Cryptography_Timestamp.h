// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "Malterlib_Cryptography_Hash.h"
#include <Mib/Container/Vector>
#include <Mib/String/String>
#include <Mib/Time/Time>

namespace NMib::NCryptography
{
	// Parsed TSTInfo structure from RFC 3161
	struct CTimestampInfo
	{
		int32 m_Version = 0;
		NStr::CStr m_Policy;
		EDigestType m_MessageImprintAlgorithm = EDigestType_SHA256;
		NContainer::CByteVector m_MessageImprint;
		NContainer::CByteVector m_SerialNumber;
		NStr::CStr m_GenTime; // GeneralizedTime as string (YYYYMMDDHHMMSSZ)
		NTime::CTime m_GenTimeUtc; // Parsed GeneralizedTime as UTC
		bool m_Ordering = false;
		NContainer::CByteVector m_Nonce;
		bool m_HasAccuracy = false;
		NTime::CTimeSpan m_Accuracy;
	};

	struct CTimestampVerificationOptions
	{
		NContainer::TCVector<NContainer::CByteVector> m_TrustedCACertificates;
		NContainer::CByteVector m_ExpectedNonce;
		NStr::CStr m_ExpectedPolicy;
		NTime::CTime m_MinimumGenTime;   // Inclusive lower bound (invalid = unused)
		NTime::CTime m_MaximumGenTime;   // Inclusive upper bound (invalid = unused)
		NTime::CTimeSpan m_MaxAccuracy;  // Maximum acceptable accuracy (invalid = unused)
		bool m_bRequireTimestampEKU = true;
		bool m_bRequireSignedAttributes = true;
		bool m_bRequireEssCertIdMatch = true;
		bool m_bRequireContentTypeAttr = true;
		bool m_bRequireMessageDigestAttr = true;
		bool m_bCheckCertificateValidityAtGenTime = true;

		bool f_HasNonce() const
		{
			return !m_ExpectedNonce.f_IsEmpty();
		}

		bool f_HasPolicy() const
		{
			return !m_ExpectedPolicy.f_IsEmpty();
		}

		bool f_HasMinimumTime() const
		{
			return m_MinimumGenTime.f_IsValid();
		}

		bool f_HasMaximumTime() const
		{
			return m_MaximumGenTime.f_IsValid();
		}

		bool f_HasAccuracyLimit() const
		{
			return m_MaxAccuracy.f_IsValid();
		}
	};

	// Parse TSTInfo from PKCS7 SignedData timestamp token
	// Throws exception on parse error
	CTimestampInfo fg_ParseTimestampToken(NContainer::CByteVector const &_TimestampToken);

	// Verify timestamp token PKCS7 signature
	// _TimestampToken: The PKCS7 SignedData timestamp token
	// _TimestampInfo: Parsed TSTInfo for contextual checks (genTime, nonce, etc)
	// _Options: Verification options and policy requirements
	// Returns true if signature is valid, throws exception on error
	bool fg_VerifyTimestampSignature
		(
			NContainer::CByteVector const &_TimestampToken
			, CTimestampInfo const &_TimestampInfo
			, CTimestampVerificationOptions const &_Options
		)
	;

	// Validate that timestamp message imprint matches expected digest
	// _TimestampInfo: Parsed timestamp info
	// _ExpectedDigest: The digest we expect to find in the timestamp
	// _ExpectedDigestType: The digest algorithm type
	// Returns true if message imprint matches, false otherwise
	bool fg_ValidateTimestampImprint
		(
			CTimestampInfo const &_TimestampInfo
			, NContainer::CByteVector const &_ExpectedDigest
			, EDigestType _ExpectedDigestType
		)
	;

	// Complete timestamp verification: parse, verify signature, and validate imprint
	// Convenience function combining all verification steps
	// Throws exception on verification failure
	CTimestampInfo fg_VerifyTimestamp
		(
			NContainer::CByteVector const &_TimestampToken
			, NContainer::CByteVector const &_ExpectedDigest
			, EDigestType _ExpectedDigestType
			, CTimestampVerificationOptions const &_Options
		)
	;

	// Compatibility overload – retains legacy signature.
	inline void fg_VerifyTimestamp
		(
			NContainer::CByteVector const &_TimestampToken
			, NContainer::CByteVector const &_ExpectedDigest
			, EDigestType _ExpectedDigestType
			, NContainer::TCVector<NContainer::CByteVector> const &_TrustedCACertificates
			, bool _bRequireTimestampEKU = true
		)
	{
		CTimestampVerificationOptions Options;
		Options.m_TrustedCACertificates = _TrustedCACertificates;
		Options.m_bRequireTimestampEKU = _bRequireTimestampEKU;
		(void)fg_VerifyTimestamp(_TimestampToken, _ExpectedDigest, _ExpectedDigestType, Options);
	}
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
