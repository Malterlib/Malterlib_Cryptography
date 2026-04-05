// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Core/Core>
#include <Mib/Cryptography/Hash>

#include "Malterlib_Cryptography_Hash_BoringSSL.h"

namespace NMib::NCryptography
{
	using CHash_MD5 = TCHashImpl<TCHashImpl_BoringSSL<EDigestType_MD5, 16>>;
	using CHashDigest_MD5 = CHash_MD5::CMessageDigest;
	extern template struct TCHashImpl_BoringSSL<EDigestType_MD5, 16>;
	extern template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_MD5, 16>>;
	extern template struct TCMessageDigest<CHash_MD5::mc_DigestSize, CHash_MD5>;
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
