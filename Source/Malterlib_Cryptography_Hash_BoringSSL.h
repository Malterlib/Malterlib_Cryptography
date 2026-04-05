// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Core/Core>
#include <Mib/Cryptography/Hash>

namespace NMib::NCryptography
{
	template <EDigestType t_DigestType, umint t_DigestSize>
	struct TCHashImpl_BoringSSL
	{
		constexpr static umint mc_DigestSize = t_DigestSize;

		TCHashImpl_BoringSSL();
		~TCHashImpl_BoringSSL();

		TCHashImpl_BoringSSL(TCHashImpl_BoringSSL const &_Other);
		TCHashImpl_BoringSSL(TCHashImpl_BoringSSL &&_Other);

		TCHashImpl_BoringSSL &operator = (TCHashImpl_BoringSSL const &_Other);
		TCHashImpl_BoringSSL &operator = (TCHashImpl_BoringSSL &&_Other);

		void f_AddData(void const *_pData, umint _Len);

		template <typename tf_CDigest>
		void f_GetDigest(tf_CDigest &o_Digest) const &;

		template <typename tf_CDigest>
		void f_GetDigest(tf_CDigest &o_Digest) &&;

		void f_Reset();

	private:
		void fp_Init();
		void fp_Destroy();

		void *mp_pContext;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
