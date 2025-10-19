// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Core/Core>
#include <Mib/Concurrency/ActorFunctor>
#include <Mib/Concurrency/ConcurrencyManager>
#include <Mib/Container/Vector>
#include <Mib/Encoding/EJson>
#include <Mib/Cryptography/Hash>

namespace NMib::NCryptography
{
	struct CTimestampOptions
	{
		NContainer::TCVector<NStr::CStr> m_TimestampURLs;
		NContainer::TCVector<NContainer::CByteVector> m_TimestampTrustedCACertificates;
	};

	NConcurrency::TCActorFunctor<NConcurrency::TCFuture<NEncoding::CEJsonSorted> ()> fg_SignFiles
		(
			NStr::CStr _FilePath
			, NContainer::CSecureByteVector _PrivateKey
			, NContainer::CByteVector _Certificate
			, EDigestType _Digest = EDigestType_SHA512
			, CTimestampOptions _TimestampOptions = {}
		)
	;

	enum class EVerifyFlag : uint32
	{
		mc_None = 0
		, mc_RequireTimestamp = DMibBit(0)

		, mc_Default = mc_RequireTimestamp
	};

	struct CVerifyOptions
	{
		EVerifyFlag m_Flags = EVerifyFlag::mc_Default;
		NContainer::TCVector<NContainer::CByteVector> m_TimestampTrustedCACertificates = {};
	};

	NConcurrency::TCActorFunctor<NConcurrency::TCFuture<void> ()> fg_VerifyFiles
		(
			NStr::CStr _FilePath
			, NEncoding::CEJsonSorted _SignatureJson
			, NContainer::TCVector<NContainer::CByteVector> _TrustedCACertificates
			, CVerifyOptions _VerifyOptions = {}
		)
	;
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
