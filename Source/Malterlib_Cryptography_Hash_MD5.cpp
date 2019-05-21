// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Container/Registry>

#include "Malterlib_Cryptography_Hash_MD5.h"
#include "Malterlib_Cryptography_Hash_BoringSSL.hpp"
#include "Malterlib_Cryptography_Hash_ImplementationPrivate.hpp"

namespace NMib::NCryptography
{
	template struct TCHashImpl_BoringSSL<EDigestType_MD5, 16>;
	template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_MD5, 16>>;
	template struct TCMessageDigest<CHash_MD5::mc_DigestSize, CHash_MD5>;
}
