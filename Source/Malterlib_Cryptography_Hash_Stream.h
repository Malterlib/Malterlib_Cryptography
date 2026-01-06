// Copyright © 2015 Hansoft AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

namespace NMib::NCryptography
{
	template <typename t_CHash, typename t_CStreamType = NStream::CBinaryStreamDefault>
	struct TCBinaryStreamHashRef : public t_CStreamType
	{
		using CDigest = typename t_CHash::CMessageDigest;;

		DMibStreamImplementOperators(TCBinaryStreamHashRef);

		TCBinaryStreamHashRef();

		void f_Reset();
		void f_Open(t_CHash *_pHash);
		void f_Open(t_CHash &_Hash);
		void f_FeedBytes(void const *_pMem, mint _nBytes);
		void f_ConsumeBytes(void *_pMem, mint _nBytes);
		bool f_IsValid() const;
		bool f_IsAtEndOfStream() const;
		mint f_ContainerLengthLimit() const;

		NStream::CFilePos f_GetLength() const;
		NStream::CFilePos f_GetPosition() const;

		void f_SetPosition(NStream::CFilePos _Pos);
		void f_SetPositionFromEnd(NStream::CFilePos _Pos);
		void f_AddPosition(NStream::CFilePos _Pos);
		bool f_IsValidReadPosition(NStream::CFilePos _Pos) const;
		void f_SetLength(NStream::CFilePos _Length);
		void f_Flush(bool _bLocalCacheOnly);
		void f_SetCacheSize(mint _CacheSize);

		CDigest f_GetDigest();

	protected:
		DMibStreamImplementProtected(TCBinaryStreamHashRef);

	private:
		inline_medium void fp_CheckOpen();

		t_CHash *mp_pHash;
	};

	template <typename t_CHash, typename t_CStreamType = NStream::CBinaryStreamDefault>
	struct TCBinaryStreamHash : public t_CStreamType
	{
		using CDigest = typename t_CHash::CMessageDigest;
		DMibStreamImplementOperators(TCBinaryStreamHash);

		TCBinaryStreamHash();

		void f_Reset();
		void f_FeedBytes(void const *_pMem, mint _nBytes);
		void f_ConsumeBytes(void *_pMem, mint _nBytes);
		bool f_IsValid() const;
		bool f_IsAtEndOfStream() const;
		mint f_ContainerLengthLimit() const;

		NStream::CFilePos f_GetLength() const;
		NStream::CFilePos f_GetPosition() const;

		void f_SetPosition(NStream::CFilePos _Pos);
		void f_SetPositionFromEnd(NStream::CFilePos _Pos);
		void f_AddPosition(NStream::CFilePos _Pos);
		bool f_IsValidReadPosition(NStream::CFilePos _Pos) const;
		void f_SetLength(NStream::CFilePos _Length);
		void f_Flush(bool _bLocalCacheOnly);
		void f_SetCacheSize(mint _CacheSize);

		CDigest f_GetDigest();

	protected:
		DMibStreamImplementProtected(TCBinaryStreamHash);

	private:
		t_CHash mp_Hash;
	};
}

#include "Malterlib_Cryptography_Hash_Stream.hpp"
