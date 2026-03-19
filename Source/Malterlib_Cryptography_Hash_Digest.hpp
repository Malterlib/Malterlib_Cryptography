// Copyright © 2015 Hansoft AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

namespace NMib::NCryptography
{
	template <umint t_Size, typename t_CHash>
	constexpr TCMessageDigest<t_Size, t_CHash>::TCMessageDigest()
	{
	}

	template <umint t_Size, typename t_CHash>
	constexpr TCMessageDigest<t_Size, t_CHash>::~TCMessageDigest()
	{
		if_not_consteval
		{
			f_Clear();
		}
	}

	template <umint t_Size, typename t_CHash>
	void TCMessageDigest<t_Size, t_CHash>::f_Clear()
	{
		NMemory::fg_SecureMemClear(mp_Data, t_Size);
	}

	template <umint t_Size, typename t_CHash>
	constexpr bool TCMessageDigest<t_Size, t_CHash>::f_IsCleared() const
	{
		for (umint i = 0; i < t_Size; ++i)
		{
			if (mp_Data[i] != 0)
				return false;
		}
		return true;
	}

	template <umint t_Size, typename t_CHash>
	constexpr TCMessageDigest<t_Size, t_CHash>::TCMessageDigest(const TCMessageDigest &_Src)
	{
		NMemory::fg_MemCopy(mp_Data, _Src.mp_Data, sizeof(mp_Data));
	}

	template <umint t_Size, typename t_CHash>
	constexpr TCMessageDigest<t_Size, t_CHash>::TCMessageDigest(t_CHash &&_Src)
	{
		fg_Move(_Src).f_GetDigest(*this);
	}

	template <umint t_Size, typename t_CHash>
	constexpr TCMessageDigest<t_Size, t_CHash>::TCMessageDigest(const t_CHash &_Src)
	{
		_Src.f_GetDigest(*this);
	}

	template <umint t_Size, typename t_CHash>
	constexpr auto TCMessageDigest<t_Size, t_CHash>::operator = (const TCMessageDigest &_Src) -> TCMessageDigest &
	{
		NMemory::fg_MemCopy(mp_Data, _Src.mp_Data, sizeof(mp_Data));
		return *this;
	}

	template <umint t_Size, typename t_CHash>
	constexpr auto TCMessageDigest<t_Size, t_CHash>::operator = (const t_CHash &_Src) -> TCMessageDigest &
	{
		_Src.f_GetDigest(*this);
		return *this;
	}

	template <umint t_Size, typename t_CHash>
	constexpr aint TCMessageDigest<t_Size, t_CHash>::f_Compare(const TCMessageDigest &_Other) const
	{
		return NMemory::fg_MemCmp(mp_Data, _Other.mp_Data, sizeof(mp_Data));
	}

	template <umint t_Size, typename t_CHash>
	constexpr bool TCMessageDigest<t_Size, t_CHash>::operator == (const TCMessageDigest &_Src) const noexcept
	{
		if (NMemory::fg_MemCmp(mp_Data, _Src.mp_Data, t_Size))
			return false;

		return true;
	}

	template <umint t_Size, typename t_CHash>
	constexpr bool TCMessageDigest<t_Size, t_CHash>::operator == (const t_CHash &_Src) const noexcept
	{
		TCMessageDigest Temp = _Src;

		return Temp == (*this);
	}

	template <umint t_Size, typename t_CHash>
	constexpr COrdering_Strong TCMessageDigest<t_Size, t_CHash>::operator <=> (const TCMessageDigest &_Src) const noexcept
	{
		return NMemory::fg_MemCmp(mp_Data, _Src.mp_Data, t_Size) <=> 0;
	}

	template <umint t_Size, typename t_CHash>
	constexpr COrdering_Strong TCMessageDigest<t_Size, t_CHash>::operator <=> (const t_CHash &_Src) const noexcept
	{
		TCMessageDigest Temp = _Src;

		return Temp <=> (*this);
	}

	template <umint t_Size, typename t_CHash>
	constexpr uint8 *TCMessageDigest<t_Size, t_CHash>::f_GetData()
	{
		return mp_Data;
	}

	template <umint t_Size, typename t_CHash>
	constexpr uint8 const *TCMessageDigest<t_Size, t_CHash>::f_GetData() const
	{
		return mp_Data;
	}

	// use:  i = h.f_FoldToInt<T>()
	// pre:  T is an integral type
	// post: up to 128 bits of 'h' have been folded circularly byte-by-byte into
	//       i using XOR
	template <umint t_Size, typename t_CHash>
	template <typename tf_CIntType>
	constexpr tf_CIntType TCMessageDigest<t_Size, t_CHash>::f_FoldToInt() const
	{
		tf_CIntType Temp = 0;
		umint IntSize = sizeof(Temp);
		umint DigestSize = t_Size;

		for (umint i = 0; i < DigestSize; ++i)
		{
			umint IntPos = i % IntSize;
			uint8 CurrentInt = (Temp >> (IntPos * 8))  & 0xff;
			uint8 CurrentDigest = mp_Data[i];
			uint8 Xored = CurrentInt ^ CurrentDigest;
			Temp = (Temp & ((~(tf_CIntType(0xff) << (IntPos *8))))) | (tf_CIntType(Xored) << (IntPos * 8));
		}
		return Temp;
	}

	template <umint t_Size, typename t_CHash>
	auto TCMessageDigest<t_Size, t_CHash>::fs_FromString(const ch8 *_pString) -> TCMessageDigest
	{
		TCMessageDigest Ret;

		Ret.f_ParseString(_pString);
		return Ret;
	}

	template <umint t_Size, typename t_CHash>
	auto TCMessageDigest<t_Size, t_CHash>::fs_FromBytes(uint8 const *_pData, umint _Len) -> TCMessageDigest
	{
		if (_Len != t_Size)
			DMibError("Invalid hash length when converting from bytes");

		TCMessageDigest Ret;
		NMemory::fg_MemCopy(Ret.mp_Data, _pData, t_Size);
		return Ret;
	}

	template <umint t_Size, typename t_CHash>
	NStr::CStr TCMessageDigest<t_Size, t_CHash>::f_GetString() const
	{
		NStr::CStr ReturnStr;
		for (umint i = 0; i < t_Size; ++i)
			ReturnStr += NStr::CStr::CFormat("{nfh,sf0,sj2}") << mp_Data[i];
		return ReturnStr;
	}

	template <umint t_Size, typename t_CHash>
	template <typename tf_CStr>
	void TCMessageDigest<t_Size, t_CHash>::f_Format(tf_CStr &o_String) const
	{
		for (umint i = 0; i < t_Size; ++i)
			o_String += typename tf_CStr::CFormat("{nfh,sf0,sj2}") << mp_Data[i];
	}

	template <umint t_Size, typename t_CHash>
	void TCMessageDigest<t_Size, t_CHash>::f_ParseString(const ch8 *_pStr)
	{
		NMemory::fg_MemClear(mp_Data);
		const ch8 *pParse = _pStr;

		for (umint i = 0; i < t_Size; ++i)
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
