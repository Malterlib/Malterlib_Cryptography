// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

#include <Mib/Core/Core>

namespace NMib::NCryptography
{
	template <mint t_Size, typename t_CHash>
	class TCMessageDigest
	{
		uint8 mp_Data[t_Size];
	public:
		TCMessageDigest()
		{
			f_Clear();
		}

		void f_Clear()
		{
			NMemory::fg_ObjectSet(mp_Data, 0, t_Size);
		}

		bint f_IsCleared() const
		{
			for (mint i = 0; i < t_Size; ++i)
			{
				if (mp_Data[i] != 0)
					return false;
			}
			return true;
		}

		TCMessageDigest(const TCMessageDigest &_Src)
		{
			NMemory::fg_MemCopy(mp_Data, _Src.mp_Data, sizeof(mp_Data));
		}

		TCMessageDigest(const t_CHash &_Src)
		{
			_Src.f_GetDigest(*this);
		}

		TCMessageDigest &operator = (const TCMessageDigest &_Src)
		{
			NMemory::fg_MemCopy(mp_Data, _Src.mp_Data, sizeof(mp_Data));
			return *this;
		}

		TCMessageDigest &operator = (const t_CHash &_Src)
		{
			_Src.f_GetDigest(*this);
			return *this;
		}

		aint f_Compare(const TCMessageDigest &_Other) const
		{
			return NMemory::fg_MemCmp(mp_Data, _Other.mp_Data, sizeof(mp_Data));
		}

		bint operator == (const TCMessageDigest &_Src) const
		{
			if (NMemory::fg_MemCmp(mp_Data, _Src.mp_Data, t_Size))
				return false;

			return true;
		}

		bint operator == (const t_CHash &_Src) const
		{
			TCMessageDigest Temp = _Src;

			return Temp == (*this);
		}

		bint operator < (const TCMessageDigest &_Src) const
		{
			return NMemory::fg_MemCmp(mp_Data, _Src.mp_Data, t_Size) < 0;
		}

		bint operator < (const t_CHash &_Src) const
		{
			TCMessageDigest Temp = _Src;

			return Temp < (*this);
		}

		static mint fs_GetSize()
		{
			return t_Size;
		}

		uint8 *f_GetData()
		{
			return mp_Data;
		}

		const uint8 *f_GetData() const
		{
			return mp_Data;
		}

		// use:  i = h.f_FoldToInt<T>()
		// pre:  T is an integral type
		// post: up to 128 bits of 'h' have been folded circularly byte-by-byte into
		//       i using XOR
		template <typename tf_CIntType>
		tf_CIntType f_FoldToInt() const
		{
			tf_CIntType Temp = 0;
			mint IntSize = sizeof(Temp);
			mint DigestSize = t_Size;

			for (mint i = 0; i < DigestSize; ++i)
			{
				mint IntPos = i % IntSize;
				uint8 CurrentInt = (Temp >> (IntPos * 8))  & 0xff;
				uint8 CurrentDigest = mp_Data[i];
				uint8 Xored = CurrentInt ^ CurrentDigest;
				Temp = (Temp & ((~(tf_CIntType(0xff) << (IntPos *8))))) | (tf_CIntType(Xored) << (IntPos * 8));
			}
			return Temp;
		}
		static TCMessageDigest fs_FromString(const ch8 *_pString)
		{
			TCMessageDigest Ret;

			Ret.f_ParseString(_pString);
			return Ret;
		}

		static TCMessageDigest fs_FromBytes(uint8 const *_pData, mint _Len)
		{
			if (_Len != t_Size)
				DMibError("Invalid hash length when converting from bytes");

			TCMessageDigest Ret;
			NMemory::fg_MemCopy(Ret.mp_Data, _pData, t_Size);
			return Ret;
		}

		NStr::CStr f_GetString() const
		{
			NStr::CStr ReturnStr;
			for (mint i = 0; i < t_Size; ++i)
				ReturnStr += NStr::CStr::CFormat("{nfh,sf0,sj2}") << mp_Data[i];
			return ReturnStr;
		}

		template <typename tf_CStr>
		void f_Format(tf_CStr &o_String) const
		{
			for (mint i = 0; i < t_Size; ++i)
				o_String += typename tf_CStr::CFormat("{nfh,sf0,sj2}") << mp_Data[i];
		}

		void f_ParseString(const ch8 *_pStr)
		{
			NMemory::fg_MemClear(mp_Data);
			const ch8 *pParse = _pStr;

			for (mint i = 0; i < t_Size; ++i)
			{
				ch8 Temp[5];
				Temp[0] = '0';
				Temp[1] = 'x';
				Temp[4] = 0;

				while (*pParse && NStr::fg_CharIsWhiteSpace(*pParse))
					++pParse;
				if (!*pParse)
					break;
				Temp[2] = *pParse;
				++pParse;
				while (*pParse && NStr::fg_CharIsWhiteSpace(*pParse))
					++pParse;
				if (!*pParse)
					break;
				Temp[3] = *pParse;
				++pParse;

				mp_Data[i] = NStr::fg_StrToInt(Temp, 0);
			}
		}
	};

	template <typename t_CHashImpl>
	class TCHashImpl
	{
	public:
		typedef TCMessageDigest<t_CHashImpl::EDigestSize, TCHashImpl> CMessageDigest;
	protected:
		typedef typename t_CHashImpl::CState CState;
		typedef typename t_CHashImpl::CData CData;

		enum
		{
			EBlockSize = t_CHashImpl::EBlockSize,
			EBlockSizeBytes = EBlockSize * sizeof(CData),
		};

	public:
		CState m_State;
		uint64 m_nBytes;
		union
		{
			uint8 m_Block[EBlockSizeBytes];
			CData m_BlockAligned[EBlockSize];
		};
		aint m_iBlockPos;
	protected:

		void fp_AddBlock(const void *_pData)
		{
//				DMibSafeCheck(!(((mint)_pData) & (DMibAlignmentOf(CData) - 1)), "Must be correct alignment");
			t_CHashImpl::fs_Transform(m_State, (const CData *)_pData);
		}

		void fp_AddData(const void *_pData, mint _Len)
		{
			m_nBytes += _Len;
			uint8 *pData = (uint8 *)_pData;
			// Start by transforming up to a whole block
			if (m_iBlockPos)
			{
				if (m_iBlockPos + _Len >= EBlockSizeBytes)
				{
					aint ToCopy = EBlockSizeBytes - m_iBlockPos;
					NMemory::fg_MemCopy(m_Block + m_iBlockPos, pData, ToCopy);
					pData += ToCopy;
					_Len -= ToCopy;

					fp_AddBlock(m_Block);
					m_iBlockPos = 0;
				}
			}

			mint Align = NTraits::TCAlignmentOf<CData>::mc_Value;
			// Add whole blocks
			if (!((mint)_pData & (Align - 1)))
			{
				while (_Len >= EBlockSizeBytes * 4)
				{
					DMibSafeCheck(m_iBlockPos == 0, "Must not have saved block");
					fp_AddBlock(pData+EBlockSizeBytes*0);
					fp_AddBlock(pData+EBlockSizeBytes*1);
					fp_AddBlock(pData+EBlockSizeBytes*2);
					fp_AddBlock(pData+EBlockSizeBytes*3);
					pData += EBlockSizeBytes*4;
					_Len -= EBlockSizeBytes*4;
				}

				while (_Len >= EBlockSizeBytes)
				{
					DMibSafeCheck(m_iBlockPos == 0, "Must not have saved block");
					fp_AddBlock(pData);
					pData += EBlockSizeBytes;
					_Len -= EBlockSizeBytes;
				}
			}
			else
			{
				while (_Len >= EBlockSizeBytes * 4)
				{
					DMibSafeCheck(m_iBlockPos == 0, "Must not have saved block");
					NMemory::fg_MemCopy(m_Block, pData+EBlockSizeBytes*0, EBlockSizeBytes);
					fp_AddBlock(m_Block);
					NMemory::fg_MemCopy(m_Block, pData+EBlockSizeBytes*1, EBlockSizeBytes);
					fp_AddBlock(m_Block);
					NMemory::fg_MemCopy(m_Block, pData+EBlockSizeBytes*2, EBlockSizeBytes);
					fp_AddBlock(m_Block);
					NMemory::fg_MemCopy(m_Block, pData+EBlockSizeBytes*3, EBlockSizeBytes);
					fp_AddBlock(m_Block);
					pData += EBlockSizeBytes*4;
					_Len -= EBlockSizeBytes*4;
				}

				while (_Len >= EBlockSizeBytes)
				{
					DMibSafeCheck(m_iBlockPos == 0, "Must not have saved block");
					NMemory::fg_MemCopy(m_Block, pData, EBlockSizeBytes);
					fp_AddBlock(pData);
					pData += EBlockSizeBytes;
					_Len -= EBlockSizeBytes;
				}
			}

			// Add remaining to buffer
			NMemory::fg_MemCopy(m_Block + m_iBlockPos, pData, _Len);
			m_iBlockPos += _Len;
		}

	public:

		TCHashImpl()
		{
			f_Reset();
		}

		TCHashImpl(const TCHashImpl &_Src)
		{
			NMemory::fg_MemCopy(m_Block, _Src.m_Block, sizeof(m_Block));
			m_State = _Src.m_State;
			m_iBlockPos = _Src.m_iBlockPos;
			m_nBytes = _Src.m_nBytes;
		}

		TCHashImpl &operator = (const TCHashImpl &_Src)
		{
			NMemory::fg_MemCopy(m_Block, _Src.m_Block, sizeof(m_Block));
			m_State = _Src.m_State;
			m_iBlockPos = _Src.m_iBlockPos;
			m_nBytes = _Src.m_nBytes;
			return *this;
		}

		~TCHashImpl()
		{
			NMemory::fg_MemClear(m_BlockAligned);
			NMemory::fg_MemClear(m_State);
		}

		void f_Reset()
		{
			NMemory::fg_MemClear(m_BlockAligned);
			m_iBlockPos = 0;
			m_nBytes = 0;

			t_CHashImpl::fs_InitState(m_State);
		}

		inline_small void f_AddData(const void *_pData, mint _Len)
		{
			fp_AddData(_pData, _Len);
		}

		void f_GetDigest(CMessageDigest &_Digest) const
		{
			// Const copy
			const TCHashImpl &TempState = *this;
			t_CHashImpl::fs_GetDigest(TempState, _Digest);
		}

		CMessageDigest f_GetDigest() const
		{
			CMessageDigest Digest;
			// Const copy
			const TCHashImpl &TempState = *this;
			t_CHashImpl::fs_GetDigest(TempState, Digest);
			return Digest;
		}

		static CMessageDigest fs_DigestFromData(const void *_pData, mint _Len)
		{
			CMessageDigest Ret;
			TCHashImpl Hash;
			Hash.f_AddData(_pData, _Len);
			Ret = Hash;
			return Ret;
		}

		static CMessageDigest fs_DigestFromData(const NContainer::CByteVector &_Data)
		{
			CMessageDigest Ret;
			TCHashImpl Hash;
			Hash.f_AddData(_Data.f_GetArray(), _Data.f_GetLen());
			Ret = Hash;
			return Ret;
		}

		static CMessageDigest fs_DigestFromStream(NStream::CBinaryStream &_Stream)
		{
			CMessageDigest Ret;
			TCHashImpl Hash;

			CMibFilePos Length = _Stream.f_GetLength();
			const int Size = 32768;
			uint8 Temp[Size];
			while (Length)
			{
				mint ThisTime = mint(fg_Min(Length, CMibFilePos(Size)));
				_Stream.f_ConsumeBytes(Temp, ThisTime);
				Hash.f_AddData(Temp, ThisTime);

				Length -= ThisTime;
			}
			NMemory::fg_MemClear(Temp);
			Ret = Hash;
			return Ret;
		}

	};


	template <typename t_CHash, typename t_CStreamType = NStream::CBinaryStreamDefault>
	class TCBinaryStreamHashRef : public t_CStreamType
	{
		t_CHash *mp_pHash;
		inline_medium void fp_CheckOpen()
		{
			if (!mp_pHash)
				DMibError("Stream not open");
		}
	protected:
		DMibStreamImplementProtected(TCBinaryStreamHashRef);
	public:
		DMibStreamImplementOperators(TCBinaryStreamHashRef);

		typedef typename t_CHash::CMessageDigest CDigest;

		TCBinaryStreamHashRef()
		{
			mp_pHash = nullptr;
		}

		void f_Reset()
		{
			mp_pHash = nullptr;
		}

		void f_Open(t_CHash *_pHash)
		{
			mp_pHash = _pHash;
		}

		void f_Open(t_CHash &_Hash)
		{
			mp_pHash = &_Hash;
		}

		void f_FeedBytes(const void *_pMem, mint _nBytes)
		{
			fp_CheckOpen();

			mp_pHash->f_AddData(_pMem, _nBytes);
		}

		void f_ConsumeBytes(void *_pMem, mint _nBytes)
		{
			DMibError("Stream does not support reading");
		}

		bint f_IsValid() const
		{
			return mp_pHash != nullptr;
		}

		bint f_IsAtEndOfStream() const
		{
			DMibError("Stream does not support positioning");
		}

		NStream::CFilePos f_GetPosition() const
		{
			DMibError("Stream does not support positioning");
		}

		void f_SetPosition(NStream::CFilePos _Pos)
		{
			DMibError("Stream does not support positioning");
		}

		void f_SetPositionFromEnd(NStream::CFilePos _Pos)
		{
			DMibError("Stream does not support positioning");
		}

		void f_AddPosition(NStream::CFilePos _Pos)
		{
			DMibError("Stream does not support positioning");
		}

		bint f_IsValidReadPosition(NStream::CFilePos _Pos) const
		{
			DMibError("Stream does not support positioning");
		}

		void f_SetLength(NStream::CFilePos _Length) { DMibError("Not supported"); }

		NStream::CFilePos f_GetLength() const
		{
			DMibError("Stream does not have a length");
		}

		void f_Flush(bint _bLocalCacheOnly)
		{
		}

		void f_SetCacheSize(mint _CacheSize)
		{
		}


		CDigest f_GetDigest()
		{
			fp_CheckOpen();
			CDigest Ret = *mp_pHash;
			return Ret;
		}
	};

	template <typename t_CHash, typename t_CStreamType = NStream::CBinaryStreamDefault>
	class TCBinaryStreamHash : public t_CStreamType
	{
		t_CHash mp_Hash;
	protected:
		DMibStreamImplementProtected(TCBinaryStreamHash);
	public:
		DMibStreamImplementOperators(TCBinaryStreamHash);

		typedef typename t_CHash::CMessageDigest CDigest;

		TCBinaryStreamHash()
		{
		}

		void f_Reset()
		{
			mp_Hash.f_Reset();
		}

		void f_FeedBytes(const void *_pMem, mint _nBytes)
		{
			mp_Hash.f_AddData(_pMem, _nBytes);
		}

		void f_ConsumeBytes(void *_pMem, mint _nBytes)
		{
			DMibError("Stream does not support reading");
		}

		bint f_IsValid() const
		{
			return true;
		}

		bint f_IsAtEndOfStream() const
		{
			DMibError("Stream does not support positioning");
		}

		NStream::CFilePos f_GetPosition() const
		{
			DMibError("Stream does not support positioning");
		}

		void f_SetPosition(NStream::CFilePos _Pos)
		{
			DMibError("Stream does not support positioning");
		}

		void f_SetPositionFromEnd(NStream::CFilePos _Pos)
		{
			DMibError("Stream does not support positioning");
		}

		void f_AddPosition(NStream::CFilePos _Pos)
		{
			DMibError("Stream does not support positioning");
		}

		bint f_IsValidReadPosition(NStream::CFilePos _Pos) const
		{
			DMibError("Stream does not support positioning");
		}

		void f_SetLength(NStream::CFilePos _Length) { DMibError("Not supported"); }

		NStream::CFilePos f_GetLength() const
		{
			DMibError("Stream does not have a length");
		}

		void f_Flush(bint _bLocalCacheOnly)
		{
		}

		void f_SetCacheSize(mint _CacheSize)
		{
		}

		CDigest f_GetDigest()
		{
			CDigest Ret = mp_Hash;
			return Ret;
		}
	};

}

namespace NMib::NStream
{
	template <typename t_CStream, mint t_Size, typename t_CHash>
	class TCBinaryStreamTypeReference<t_CStream, NCryptography::TCMessageDigest<t_Size, t_CHash> >
	{
	public:
		static void fs_Feed(t_CStream &_Stream, NCryptography::TCMessageDigest<t_Size, t_CHash> const &_Data)
		{
			_Stream.f_FeedBytes(_Data.f_GetData(), t_Size);
		}
		static void fs_Consume(t_CStream &_Stream, NCryptography::TCMessageDigest<t_Size, t_CHash> &_Data)
		{
			_Stream.f_ConsumeBytes(_Data.f_GetData(), t_Size);
		}
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
