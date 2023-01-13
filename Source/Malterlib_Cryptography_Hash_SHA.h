// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

#include <Mib/Core/Core>
#include <Mib/Cryptography/Hash>

#include "Malterlib_Cryptography_Hash_BoringSSL.h"

namespace NMib::NCryptography
{
	using CHash_SHA256_16 = TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA256_16, 16>>;
	using CHashDigest_SHA256_16 = CHash_SHA256_16::CMessageDigest;
	extern template struct TCHashImpl_BoringSSL<EDigestType_SHA256_16, 16>;
	extern template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA256_16, 16>>;
	extern template struct TCMessageDigest<CHash_SHA256_16::mc_DigestSize, CHash_SHA256_16>;

	using CHash_SHA1 = TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA1, 20>>;
	using CHashDigest_SHA1 = CHash_SHA1::CMessageDigest;
	extern template struct TCHashImpl_BoringSSL<EDigestType_SHA1, 20>;
	extern template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA1, 20>>;
	extern template struct TCMessageDigest<CHash_SHA1::mc_DigestSize, CHash_SHA1>;

	typedef TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA224, 28>> CHash_SHA224;
	typedef CHash_SHA224::CMessageDigest CHashDigest_SHA224;
	extern template struct TCHashImpl_BoringSSL<EDigestType_SHA224, 28>;
	extern template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA224, 28>>;
	extern template struct TCMessageDigest<CHash_SHA224::mc_DigestSize, CHash_SHA224>;

	typedef TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA256, 32>> CHash_SHA256;
	typedef CHash_SHA256::CMessageDigest CHashDigest_SHA256;
	extern template struct TCHashImpl_BoringSSL<EDigestType_SHA256, 32>;
	extern template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA256, 32>>;
	extern template struct TCMessageDigest<CHash_SHA256::mc_DigestSize, CHash_SHA256>;

	typedef TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA384, 48>> CHash_SHA384;
	typedef CHash_SHA384::CMessageDigest CHashDigest_SHA384;
	extern template struct TCHashImpl_BoringSSL<EDigestType_SHA384, 48>;
	extern template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA384, 48>>;
	extern template struct TCMessageDigest<CHash_SHA384::mc_DigestSize, CHash_SHA384>;

	typedef TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA512, 64>> CHash_SHA512;
	typedef CHash_SHA512::CMessageDigest CHashDigest_SHA512;
	extern template struct TCHashImpl_BoringSSL<EDigestType_SHA512, 64>;
	extern template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA512, 64>>;
	extern template struct TCMessageDigest<CHash_SHA512::mc_DigestSize, CHash_SHA512>;
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
