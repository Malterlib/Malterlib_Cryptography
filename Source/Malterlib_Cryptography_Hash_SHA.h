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

	using CHash_SHA224 = TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA224, 28>>;
	using CHashDigest_SHA224 = CHash_SHA224::CMessageDigest;
	extern template struct TCHashImpl_BoringSSL<EDigestType_SHA224, 28>;
	extern template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA224, 28>>;
	extern template struct TCMessageDigest<CHash_SHA224::mc_DigestSize, CHash_SHA224>;

	using CHash_SHA256 = TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA256, 32>>;
	using CHashDigest_SHA256 = CHash_SHA256::CMessageDigest;
	extern template struct TCHashImpl_BoringSSL<EDigestType_SHA256, 32>;
	extern template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA256, 32>>;
	extern template struct TCMessageDigest<CHash_SHA256::mc_DigestSize, CHash_SHA256>;

	using CHash_SHA384 = TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA384, 48>>;
	using CHashDigest_SHA384 = CHash_SHA384::CMessageDigest;
	extern template struct TCHashImpl_BoringSSL<EDigestType_SHA384, 48>;
	extern template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA384, 48>>;
	extern template struct TCMessageDigest<CHash_SHA384::mc_DigestSize, CHash_SHA384>;

	using CHash_SHA512 = TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA512, 64>>;
	using CHashDigest_SHA512 = CHash_SHA512::CMessageDigest;
	extern template struct TCHashImpl_BoringSSL<EDigestType_SHA512, 64>;
	extern template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA512, 64>>;
	extern template struct TCMessageDigest<CHash_SHA512::mc_DigestSize, CHash_SHA512>;
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
