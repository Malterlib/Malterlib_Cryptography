// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

namespace NMib::NCryptography
{
	template <typename t_CHashImpl>
	inline_small void TCHashImpl<t_CHashImpl>::f_AddData(void const *_pData, umint _Len)
	{
		mp_Implementation.f_AddData(_pData, _Len);
	}

	template <typename t_CHashImpl>
	void TCHashImpl<t_CHashImpl>::f_GetDigest(CMessageDigest &_Digest) const &
	{
		mp_Implementation.f_GetDigest(_Digest);
	}

	template <typename t_CHashImpl>
	void TCHashImpl<t_CHashImpl>::f_GetDigest(CMessageDigest &_Digest) &&
	{
		fg_Move(mp_Implementation).f_GetDigest(_Digest);
	}

	template <typename t_CHashImpl>
	auto TCHashImpl<t_CHashImpl>::f_GetDigest() const & -> CMessageDigest
	{
		CMessageDigest Digest;
		mp_Implementation.f_GetDigest(Digest);
		return Digest;
	}

	template <typename t_CHashImpl>
	auto TCHashImpl<t_CHashImpl>::f_GetDigest() && -> CMessageDigest
	{
		CMessageDigest Digest;
		fg_Move(mp_Implementation).f_GetDigest(Digest);
		return Digest;
	}
}
