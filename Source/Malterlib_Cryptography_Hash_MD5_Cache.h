// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "Malterlib_Cryptography_Hash_MD5.h"

namespace NMib::NCryptography
{
	struct CHashCache
	{
		CHashCache(NStr::CStr const &_File, bool _bUpdateHash, bool _bAlwaysCheckHash);
		~CHashCache();

		bool f_SetAlwaysCheckHash(bool _bAlwaysCheck);

		void f_SaveToFile(NStr::CStr const &_File);
		CHashDigest_MD5 f_GetHash(NStr::CStr const &_FileName, NStr::CStr const &_AlternateFileName = NStr::CStr());
		void f_SetHash(NStr::CStr const &_FileName, CHashDigest_MD5 const &_Digest);
		void f_ClearPrefix(NStr::CStr const &_Prefix);

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
