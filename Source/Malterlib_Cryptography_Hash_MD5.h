// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

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

	struct CHashCache
	{
		CHashCache(NStr::CStr const &_File, bool _bUpdateHash, bool _bAlwaysCheckHash);
		~CHashCache();

		bool f_SetAlwaysCheckHash(bool _bAlwaysCheck);

		void f_SaveToFile(NStr::CStr const &_File);
		CHashDigest_MD5 f_GetHash(NStr::CStr const &_FileName, NStr::CStr const &_AlternateFileName = NStr::CStr());
		void f_SetHash(NStr::CStr const &_FileName, CHashDigest_MD5 const &_Digest);

	private:
		NStr::CStr mp_HashFileName;
		bool mp_bUpdateHash;
		bool mp_bAlwaysCheckHash;
		NContainer::TCMap<NStr::CStr, CHashDigest_MD5> mp_CachedDigests;
		NThread::CMutual mp_Lock;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
