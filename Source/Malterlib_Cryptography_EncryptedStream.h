// Copyright © 2018 Nonna Holding AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

#include <Mib/Core/Core>
#include <Mib/Cryptography/KeyDerivation>
#include <Mib/Cryptography/SymmetricCrypto>
#include "Malterlib_Cryptography_Exception.h"

namespace NMib::NCryptography
{
	template <typename t_CParentStream, typename t_CStreamType = NStream::CBinaryStreamDefault>
	class TCBinaryStream_Encrypted : public t_CStreamType
	{
	public:

		TCBinaryStream_Encrypted(CEncryptKeyIV const &_KeyIV, EDigestType _HMAC, NContainer::CSecureByteVector const &_HMACKey);
		~TCBinaryStream_Encrypted();

		template <typename tf_CParentStream>
		void f_Open(tf_CParentStream &&_pStream, NFile::EFileOpen _OpenFlags);
		void f_Close();
		void f_FeedBytes(const void *_pMem, mint _nBytes);
		void f_ConsumeBytes(void *_pMem, mint _nBytes);
		bool f_IsValid() const;
		bool f_IsAtEndOfStream() const;
		NStream::CFilePos f_GetPosition() const;
		void f_SetPosition(NStream::CFilePos _Pos);
		void f_SetPositionFromEnd(NStream::CFilePos _Pos);
		void f_AddPosition(NStream::CFilePos _Pos);
		bool f_IsValidReadPosition(NStream::CFilePos _Pos) const;
		void f_Flush(bool _bLocalCacheOnly);
		void f_SetCacheSize(mint _CacheSize);
		NStream::CFilePos f_GetLength() const;
		mint f_ContainerLengthLimit() const;
		void f_SetLength(NStream::CFilePos _Length);
		void f_SetBufferSize(mint _BufferSize); // For testing only

		DMibStreamImplementOperators(TCBinaryStream_Encrypted);

	protected:
		DMibStreamImplementProtected(TCBinaryStream_Encrypted);

	private:
		void fp_WriteDirty(bool _bFinalize);
		mint fp_PrepareBlock(NStream::CFilePos _Pos, bool _bWrite);
		decltype(auto) fp_GetParentStream() const;

		enum
		{
			EDefaultBufferSize = 8192,
		};

		t_CParentStream mp_Stream = t_CParentStream();
		NStorage::TCUniquePointer<CIncrementalEncrypt> mp_pEncryptContext;
		NStorage::TCUniquePointer<CIncrementalHMAC> mp_pHMACContext;

		NContainer::CSecureByteVector mp_DecryptedBlock;
		NContainer::CSecureByteVector mp_TempBlock;
		CEncryptKeyIV const mp_KeyIV;
		NContainer::CSecureByteVector mp_HMACKey;

		NStream::CFilePos mp_FilePos = 0;
		NStream::CFilePos mp_CurrentLoaded = -1;
		NStream::CFilePos mp_LastLoaded = 0;
		NStream::CFilePos mp_FileLen = 0;
		NStream::CFilePos mp_EncryptedFileLen = 0;
		mint mp_BufferSize = EDefaultBufferSize;
		mint mp_BlockSize;

		EDigestType mp_HMAC = EDigestType_None;
		NFile::EFileOpen mp_OpenFlags = NFile::EFileOpen_None;

		bool mp_bCurrentDirty = false;
		bool mp_bNeedsFinalization = false;
		bool mp_bCanChangePosition = false;
		bool mp_bIsCBC = false;
		bool mp_bIsECB = false;
	};
}

#include "Malterlib_Cryptography_EncryptedStream.hpp"

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
