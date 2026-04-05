// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Core/Core>

namespace NMib::NCryptography
{
	enum EDigestType
	{
		EDigestType_None
		, EDigestType_Automatic
		, EDigestType_SHA512
		, EDigestType_SHA384
		, EDigestType_SHA256
		, EDigestType_SHA224
		, EDigestType_SHA1		// Be careful, only to be used for compatibility with legacy systems (borken hash)
		, EDigestType_MD5		// Be careful, only to be used for compatibility with legacy systems (borken hash)
		, EDigestType_MD4		// Be careful, only to be used for compatibility with legacy systems (borken hash)
		, EDigestType_SHA256_16	// Use first 16 bytes of SHA256
	};

	template <umint t_Size, typename t_CHash>
	struct TCMessageDigest
	{
		constexpr TCMessageDigest();
		constexpr ~TCMessageDigest();
		constexpr TCMessageDigest(TCMessageDigest const &_Src);
		constexpr TCMessageDigest(t_CHash const &_Src);
		constexpr TCMessageDigest(t_CHash &&_Src);
		constexpr TCMessageDigest &operator = (TCMessageDigest const &_Src);
		constexpr TCMessageDigest &operator = (t_CHash const &_Src);

		void f_Clear();
		constexpr bool f_IsCleared() const;

		constexpr aint f_Compare(TCMessageDigest const &_Other) const;
		constexpr bool operator == (TCMessageDigest const &_Src) const noexcept;
		constexpr bool operator == (t_CHash const &_Src) const noexcept;
		constexpr COrdering_Strong operator <=> (TCMessageDigest const &_Src) const noexcept;
		constexpr COrdering_Strong operator <=> (t_CHash const &_Src) const noexcept;

		constexpr uint8 *f_GetData();
		constexpr uint8 const *f_GetData() const;

		template <typename tf_CIntType>
		constexpr tf_CIntType f_FoldToInt() const;

		static TCMessageDigest fs_FromString(ch8 const *_pString);
		static TCMessageDigest fs_FromBytes(uint8 const *_pData, umint _Len);

		NStr::CStr f_GetString() const;
		template <typename tf_CStr>
		void f_Format(tf_CStr &o_String) const;
		void f_ParseString(ch8 const *_pStr);

		constexpr static umint mc_Size = t_Size;

	private:
		uint8 mp_Data[t_Size] = {0};
	};

	template <typename t_CHashImpl>
	struct TCHashImpl
	{
		constexpr static umint mc_DigestSize = t_CHashImpl::mc_DigestSize;

		using CMessageDigest = TCMessageDigest<mc_DigestSize, TCHashImpl>;

		TCHashImpl();
		TCHashImpl(TCHashImpl const &);
		TCHashImpl(TCHashImpl &&);
		TCHashImpl &operator = (TCHashImpl const &);
		TCHashImpl &operator = (TCHashImpl &&);

		void f_Reset();
		inline_small void f_AddData(void const *_pData, umint _Len);
		void f_GetDigest(CMessageDigest &_Digest) const &;
		void f_GetDigest(CMessageDigest &_Digest) &&;
		CMessageDigest f_GetDigest() const &;
		CMessageDigest f_GetDigest() &&;

		static CMessageDigest fs_DigestFromData(void const *_pData, umint _Len);
		static CMessageDigest fs_DigestFromData(NContainer::CByteVector const &_Data);
		static CMessageDigest fs_DigestFromData(NContainer::CSecureByteVector const &_Data);
		static CMessageDigest fs_DigestFromStream(NStream::CBinaryStream &_Stream);

	private:
		t_CHashImpl mp_Implementation;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif

#include "Malterlib_Cryptography_Hash_Stream.h"
#include "Malterlib_Cryptography_Hash_Digest.hpp"
#include "Malterlib_Cryptography_Hash_Implementation.hpp"
