// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include "Malterlib_Cryptography_Hash_SHA.h"
#include "Malterlib_Cryptography_Hash_BoringSSL.hpp"
#include "Malterlib_Cryptography_Hash_ImplementationPrivate.hpp"

namespace NMib::NCryptography
{
	template struct TCHashImpl_BoringSSL<EDigestType_SHA256_16, 16>;
	template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA256_16, 16>>;
	template struct TCMessageDigest<CHash_SHA256_16::mc_DigestSize, CHash_SHA256_16>;
	template struct TCHashImpl_BoringSSL<EDigestType_SHA1, 20>;
	template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA1, 20>>;
	template struct TCMessageDigest<CHash_SHA1::mc_DigestSize, CHash_SHA1>;
	template struct TCHashImpl_BoringSSL<EDigestType_SHA224, 28>;
	template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA224, 28>>;
	template struct TCMessageDigest<CHash_SHA224::mc_DigestSize, CHash_SHA224>;
	template struct TCHashImpl_BoringSSL<EDigestType_SHA256, 32>;
	template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA256, 32>>;
	template struct TCMessageDigest<CHash_SHA256::mc_DigestSize, CHash_SHA256>;
	template struct TCHashImpl_BoringSSL<EDigestType_SHA384, 48>;
	template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA384, 48>>;
	template struct TCMessageDigest<CHash_SHA384::mc_DigestSize, CHash_SHA384>;
	template struct TCHashImpl_BoringSSL<EDigestType_SHA512, 64>;
	template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_SHA512, 64>>;
	template struct TCMessageDigest<CHash_SHA512::mc_DigestSize, CHash_SHA512>;
}
