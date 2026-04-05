// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

namespace NMib::NCryptography
{
	template <typename t_CHash, typename t_CStreamType>
	inline_medium void TCBinaryStreamHashRef<t_CHash, t_CStreamType>::fp_CheckOpen()
	{
		if (!mp_pHash)
			DMibError("Stream not open");
	}

	template <typename t_CHash, typename t_CStreamType>
	TCBinaryStreamHashRef<t_CHash, t_CStreamType>::TCBinaryStreamHashRef()
	{
		mp_pHash = nullptr;
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_Reset()
	{
		mp_pHash = nullptr;
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_Open(t_CHash *_pHash)
	{
		mp_pHash = _pHash;
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_Open(t_CHash &_Hash)
	{
		mp_pHash = &_Hash;
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_FeedBytes(void const *_pMem, umint _nBytes)
	{
		fp_CheckOpen();

		mp_pHash->f_AddData(_pMem, _nBytes);
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_ConsumeBytes(void *_pMem, umint _nBytes)
	{
		DMibError("Stream does not support reading");
	}

	template <typename t_CHash, typename t_CStreamType>
	bool TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_IsValid() const
	{
		return mp_pHash != nullptr;
	}

	template <typename t_CHash, typename t_CStreamType>
	bool TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_IsAtEndOfStream() const
	{
		DMibError("Stream does not support positioning");
	}

	template <typename t_CHash, typename t_CStreamType>
	umint TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_ContainerLengthLimit() const
	{
		DMibError("Stream does not support reading");
		return 0;
	}

	template <typename t_CHash, typename t_CStreamType>
	NStream::CFilePos TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_GetPosition() const
	{
		DMibError("Stream does not support positioning");
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_SetPosition(NStream::CFilePos _Pos)
	{
		DMibError("Stream does not support positioning");
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_SetPositionFromEnd(NStream::CFilePos _Pos)
	{
		DMibError("Stream does not support positioning");
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_AddPosition(NStream::CFilePos _Pos)
	{
		DMibError("Stream does not support positioning");
	}

	template <typename t_CHash, typename t_CStreamType>
	bool TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_IsValidReadPosition(NStream::CFilePos _Pos) const
	{
		DMibError("Stream does not support positioning");
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_SetLength(NStream::CFilePos _Length)
	{
		DMibError("Not supported");
	}

	template <typename t_CHash, typename t_CStreamType>
	NStream::CFilePos TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_GetLength() const
	{
		DMibError("Stream does not have a length");
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_Flush(bool _bLocalCacheOnly)
	{
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_SetCacheSize(umint _CacheSize)
	{
	}

	template <typename t_CHash, typename t_CStreamType>
	auto TCBinaryStreamHashRef<t_CHash, t_CStreamType>::f_GetDigest() -> CDigest
	{
		fp_CheckOpen();
		CDigest Ret = *mp_pHash;
		return Ret;
	}

	//

	template <typename t_CHash, typename t_CStreamType>
	TCBinaryStreamHash<t_CHash, t_CStreamType>::TCBinaryStreamHash()
	{
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHash<t_CHash, t_CStreamType>::f_Reset()
	{
		mp_Hash.f_Reset();
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHash<t_CHash, t_CStreamType>::f_FeedBytes(void const *_pMem, umint _nBytes)
	{
		mp_Hash.f_AddData(_pMem, _nBytes);
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHash<t_CHash, t_CStreamType>::f_ConsumeBytes(void *_pMem, umint _nBytes)
	{
		DMibError("Stream does not support reading");
	}

	template <typename t_CHash, typename t_CStreamType>
	bool TCBinaryStreamHash<t_CHash, t_CStreamType>::f_IsValid() const
	{
		return true;
	}

	template <typename t_CHash, typename t_CStreamType>
	bool TCBinaryStreamHash<t_CHash, t_CStreamType>::f_IsAtEndOfStream() const
	{
		DMibError("Stream does not support positioning");
	}

	template <typename t_CHash, typename t_CStreamType>
	umint TCBinaryStreamHash<t_CHash, t_CStreamType>::f_ContainerLengthLimit() const
	{
		DMibError("Stream does not support reading");
		return 0;
	}

	template <typename t_CHash, typename t_CStreamType>
	NStream::CFilePos TCBinaryStreamHash<t_CHash, t_CStreamType>::f_GetPosition() const
	{
		DMibError("Stream does not support positioning");
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHash<t_CHash, t_CStreamType>::f_SetPosition(NStream::CFilePos _Pos)
	{
		DMibError("Stream does not support positioning");
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHash<t_CHash, t_CStreamType>::f_SetPositionFromEnd(NStream::CFilePos _Pos)
	{
		DMibError("Stream does not support positioning");
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHash<t_CHash, t_CStreamType>::f_AddPosition(NStream::CFilePos _Pos)
	{
		DMibError("Stream does not support positioning");
	}

	template <typename t_CHash, typename t_CStreamType>
	bool TCBinaryStreamHash<t_CHash, t_CStreamType>::f_IsValidReadPosition(NStream::CFilePos _Pos) const
	{
		DMibError("Stream does not support positioning");
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHash<t_CHash, t_CStreamType>::f_SetLength(NStream::CFilePos _Length)
	{
		DMibError("Not supported");
	}

	template <typename t_CHash, typename t_CStreamType>
	NStream::CFilePos TCBinaryStreamHash<t_CHash, t_CStreamType>::f_GetLength() const
	{
		DMibError("Stream does not have a length");
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHash<t_CHash, t_CStreamType>::f_Flush(bool _bLocalCacheOnly)
	{
	}

	template <typename t_CHash, typename t_CStreamType>
	void TCBinaryStreamHash<t_CHash, t_CStreamType>::f_SetCacheSize(umint _CacheSize)
	{
	}

	template <typename t_CHash, typename t_CStreamType>
	auto TCBinaryStreamHash<t_CHash, t_CStreamType>::f_GetDigest() -> CDigest
	{
		CDigest Ret = mp_Hash;
		return Ret;
	}
}

namespace NMib::NStream
{
	template <typename t_CStream, umint t_Size, typename t_CHash>
	class TCBinaryStreamTypeReference<t_CStream, NCryptography::TCMessageDigest<t_Size, t_CHash>>
	{
	public:
		static constexpr void fs_Feed(t_CStream &_Stream, NCryptography::TCMessageDigest<t_Size, t_CHash> const &_Data)
		{
			_Stream.f_FeedBytes(_Data.f_GetData(), t_Size);
		}
		static constexpr void fs_Consume(t_CStream &_Stream, NCryptography::TCMessageDigest<t_Size, t_CHash> &_Data)
		{
			_Stream.f_ConsumeBytes(_Data.f_GetData(), t_Size);
		}
	};
}
