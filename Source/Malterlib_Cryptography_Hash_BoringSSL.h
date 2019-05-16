// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

#include <Mib/Core/Core>
#include <Mib/Cryptography/Hash>

namespace NMib::NCryptography
{
	template <EDigestType t_DigestType, mint t_DigestSize>
	struct TCHashImpl_BoringSSL
	{
		constexpr static mint mc_DigestSize = t_DigestSize;

		TCHashImpl_BoringSSL();
		~TCHashImpl_BoringSSL();

		TCHashImpl_BoringSSL(TCHashImpl_BoringSSL const &_Other);
		TCHashImpl_BoringSSL(TCHashImpl_BoringSSL &&_Other);

		TCHashImpl_BoringSSL &operator = (TCHashImpl_BoringSSL const &_Other);
		TCHashImpl_BoringSSL &operator = (TCHashImpl_BoringSSL &&_Other);

		void f_AddData(void const *_pData, mint _Len);

		template <typename tf_CDigest>
		void f_GetDigest(tf_CDigest &o_Digest) const;

	private:
		void fp_Init();
		void fp_Destroy();

		void *mp_pContext;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
