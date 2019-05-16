// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include "Malterlib_Cryptography_Hash_MD5.h"
#include "Malterlib_Cryptography_Hash_BoringSSL.hpp"
#include "Malterlib_Cryptography_Hash_ImplementationPrivate.hpp"

namespace NMib::NCryptography
{
	template struct TCHashImpl_BoringSSL<EDigestType_MD5, 16>;
	template struct TCHashImpl<TCHashImpl_BoringSSL<EDigestType_MD5, 16>>;
	template struct TCMessageDigest<CHash_MD5::mc_DigestSize, CHash_MD5>;

	namespace NPrivate
	{
		NStr::CStr fg_GetConsistentPath(NStr::CStr const &_Path)
		{
#ifdef DPlatformFamily_Windows
			return NMib::NFile::CFile::fs_GetMalterlibPath(_Path).f_LowerCase();
#else
			return NMib::NFile::CFile::fs_GetMalterlibPath(_Path);
#endif
		}
	}

	CHashCache::CHashCache(NStr::CStr const &_File, bool _bUpdateHash, bool _bAlwaysCheckHash)
			: mp_HashFileName(_File)
			, mp_bUpdateHash(_bUpdateHash)
			, mp_bAlwaysCheckHash(_bAlwaysCheckHash)
	{
		if (!_File.f_IsEmpty() && NFile::CFile::fs_FileExists(_File))
		{
			DMibLog(Debug, "Reading hash cache from: {}", _File);
			NContainer::CRegistry_CStr Hash;
			NStr::CStr FileData = NFile::CFile::fs_ReadStringFromFile(NStr::CStr(mp_HashFileName));
			Hash.f_ParseStr(FileData, mp_HashFileName);

			for (auto iHash = Hash.f_GetChildIterator(); iHash; ++iHash)
				mp_CachedDigests[NPrivate::fg_GetConsistentPath(iHash->f_GetName())] = CHashDigest_MD5::fs_FromString(iHash->f_GetThisValue());
		}
		else
			DMibLog(Debug, "Hash cache file not found: {}", _File);
	}

	CHashCache::~CHashCache()
	{
		if (!mp_HashFileName.f_IsEmpty() && mp_bUpdateHash)
		{
			f_SaveToFile(mp_HashFileName);
		}
	}

	bool CHashCache::f_SetAlwaysCheckHash(bool _bAlwaysCheck)
	{
		DMibLock(mp_Lock);
		bool bRet = mp_bAlwaysCheckHash;
		mp_bAlwaysCheckHash = _bAlwaysCheck;
		return bRet;
	}

	void CHashCache::f_SaveToFile(NStr::CStr const &_File)
	{
		DMibLock(mp_Lock);
		NContainer::CRegistry_CStr Hash;
		if (NFile::CFile::fs_FileExists(_File))
		{
			NStr::CStr FileData = NFile::CFile::fs_ReadStringFromFile(NStr::CStr(_File));
			Hash.f_ParseStr(FileData, _File);
		}

		for (auto iHash = mp_CachedDigests.f_GetIterator(); iHash; ++iHash)
			Hash.f_SetValueNoPath(iHash.f_GetKey(), iHash->f_GetString());

		NFile::CFile::fs_WriteStringToFile(NStr::CStr(_File), Hash.f_GenerateStr());
	}

	void CHashCache::f_SetHash(NStr::CStr const &_FileName, CHashDigest_MD5 const &_Digest)
	{
		DMibLock(mp_Lock);
		NStr::CStr ConsistentName = NPrivate::fg_GetConsistentPath(_FileName);
		DMibLog(Debug, "SETTING HASH: {}", ConsistentName);
		mp_CachedDigests[ConsistentName] = _Digest;
	}

	CHashDigest_MD5 CHashCache::f_GetHash(NStr::CStr const &_FileName, NStr::CStr const &_AlternameFileName)
	{
		NStr::CStr ConsistentName = NPrivate::fg_GetConsistentPath(_FileName);
		DMibLock(mp_Lock);
		if (!mp_bAlwaysCheckHash)
		{
			// Check if file has already been hashed
			auto pHash = mp_CachedDigests.f_FindEqual(ConsistentName);
			if (pHash)
			{
				DMibLog(Debug, "HASH CACHED: {}", ConsistentName);
				return *pHash;
			}

			DMibLog(Debug, "HASH not found: {}", ConsistentName);

			// Check if file was copied from a location that has already been hashed
			NStr::CStr ConsistentAlternateName = NPrivate::fg_GetConsistentPath(_AlternameFileName);
			if (!ConsistentAlternateName.f_IsEmpty())
			{
				pHash = mp_CachedDigests.f_FindEqual(ConsistentAlternateName);
				if (pHash)
				{
					mp_CachedDigests[ConsistentName] = *pHash;
					return *pHash;
				}
			}

		}

		CHashDigest_MD5 Digest;
		{
			DMibUnlock(mp_Lock);
			Digest = NFile::CFile::fs_GetFileChecksum(_FileName);
		}
		DMibLog(Debug, "HASHING: {}", ConsistentName);

		mp_CachedDigests[ConsistentName] = Digest;
		return Digest;
	}
}
