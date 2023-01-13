// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

namespace NMib::NCryptography
{
	template <mint t_Size, typename t_CHash>
	constexpr TCMessageDigest<t_Size, t_CHash>::TCMessageDigest()
	{
	}

	template <mint t_Size, typename t_CHash>
	constexpr TCMessageDigest<t_Size, t_CHash>::~TCMessageDigest()
	{
		if (!std::is_constant_evaluated())
			f_Clear();
	}

	template <mint t_Size, typename t_CHash>
	void TCMessageDigest<t_Size, t_CHash>::f_Clear()
	{
		NMemory::fg_SecureMemClear(mp_Data, t_Size);
	}

	template <mint t_Size, typename t_CHash>
	constexpr bool TCMessageDigest<t_Size, t_CHash>::f_IsCleared() const
	{
		for (mint i = 0; i < t_Size; ++i)
		{
			if (mp_Data[i] != 0)
				return false;
		}
		return true;
	}

	template <mint t_Size, typename t_CHash>
	constexpr TCMessageDigest<t_Size, t_CHash>::TCMessageDigest(const TCMessageDigest &_Src)
	{
		NMemory::fg_MemCopy(mp_Data, _Src.mp_Data, sizeof(mp_Data));
	}

	template <mint t_Size, typename t_CHash>
	TCMessageDigest<t_Size, t_CHash>::TCMessageDigest(const t_CHash &_Src)
	template <mint t_Size, typename t_CHash>
	constexpr TCMessageDigest<t_Size, t_CHash>::TCMessageDigest(const t_CHash &_Src)
	{
		_Src.f_GetDigest(*this);
	}

	template <mint t_Size, typename t_CHash>
	constexpr auto TCMessageDigest<t_Size, t_CHash>::operator = (const TCMessageDigest &_Src) -> TCMessageDigest &
	{
		NMemory::fg_MemCopy(mp_Data, _Src.mp_Data, sizeof(mp_Data));
		return *this;
	}

	template <mint t_Size, typename t_CHash>
	constexpr auto TCMessageDigest<t_Size, t_CHash>::operator = (const t_CHash &_Src) -> TCMessageDigest &
	{
		_Src.f_GetDigest(*this);
		return *this;
	}

	template <mint t_Size, typename t_CHash>
	constexpr aint TCMessageDigest<t_Size, t_CHash>::f_Compare(const TCMessageDigest &_Other) const
	{
		return NMemory::fg_MemCmp(mp_Data, _Other.mp_Data, sizeof(mp_Data));
	}

	template <mint t_Size, typename t_CHash>
	constexpr bool TCMessageDigest<t_Size, t_CHash>::operator == (const TCMessageDigest &_Src) const
	{
		if (NMemory::fg_MemCmp(mp_Data, _Src.mp_Data, t_Size))
			return false;

		return true;
	}

	template <mint t_Size, typename t_CHash>
	constexpr bool TCMessageDigest<t_Size, t_CHash>::operator == (const t_CHash &_Src) const
	{
		TCMessageDigest Temp = _Src;

		return Temp == (*this);
	}

	template <mint t_Size, typename t_CHash>
	constexpr COrdering_Strong TCMessageDigest<t_Size, t_CHash>::operator <=> (const TCMessageDigest &_Src) const
	{
		return NMemory::fg_MemCmp(mp_Data, _Src.mp_Data, t_Size) <=> 0;
	}

	template <mint t_Size, typename t_CHash>
	constexpr COrdering_Strong TCMessageDigest<t_Size, t_CHash>::operator <=> (const t_CHash &_Src) const
	{
		TCMessageDigest Temp = _Src;

		return Temp <=> (*this);
	}

	template <mint t_Size, typename t_CHash>
	constexpr mint TCMessageDigest<t_Size, t_CHash>::fs_GetSize()
	{
		return t_Size;
	}

	template <mint t_Size, typename t_CHash>
	constexpr uint8 *TCMessageDigest<t_Size, t_CHash>::f_GetData()
	{
		return mp_Data;
	}

	template <mint t_Size, typename t_CHash>
	constexpr uint8 const *TCMessageDigest<t_Size, t_CHash>::f_GetData() const
	{
		return mp_Data;
	}

	// use:  i = h.f_FoldToInt<T>()
	// pre:  T is an integral type
	// post: up to 128 bits of 'h' have been folded circularly byte-by-byte into
	//       i using XOR
	template <mint t_Size, typename t_CHash>
	template <typename tf_CIntType>
	constexpr tf_CIntType TCMessageDigest<t_Size, t_CHash>::f_FoldToInt() const
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

	template <mint t_Size, typename t_CHash>
	auto TCMessageDigest<t_Size, t_CHash>::fs_FromString(const ch8 *_pString) -> TCMessageDigest
	{
		TCMessageDigest Ret;

		Ret.f_ParseString(_pString);
		return Ret;
	}

	template <mint t_Size, typename t_CHash>
	auto TCMessageDigest<t_Size, t_CHash>::fs_FromBytes(uint8 const *_pData, mint _Len) -> TCMessageDigest
	{
		if (_Len != t_Size)
			DMibError("Invalid hash length when converting from bytes");

		TCMessageDigest Ret;
		NMemory::fg_MemCopy(Ret.mp_Data, _pData, t_Size);
		return Ret;
	}

	template <mint t_Size, typename t_CHash>
	NStr::CStr TCMessageDigest<t_Size, t_CHash>::f_GetString() const
	{
		NStr::CStr ReturnStr;
		for (mint i = 0; i < t_Size; ++i)
			ReturnStr += NStr::CStr::CFormat("{nfh,sf0,sj2}") << mp_Data[i];
		return ReturnStr;
	}

	template <mint t_Size, typename t_CHash>
	template <typename tf_CStr>
	void TCMessageDigest<t_Size, t_CHash>::f_Format(tf_CStr &o_String) const
	{
		for (mint i = 0; i < t_Size; ++i)
			o_String += typename tf_CStr::CFormat("{nfh,sf0,sj2}") << mp_Data[i];
	}

	template <mint t_Size, typename t_CHash>
	void TCMessageDigest<t_Size, t_CHash>::f_ParseString(const ch8 *_pStr)
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
}
