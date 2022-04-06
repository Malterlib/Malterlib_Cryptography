// Copyright © 2019 Nonna Holding AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include "Malterlib_Cryptography_BoringSSL.h"

namespace NMib::NCryptography
{
	using namespace NBoringSSL;

	static EVP_MD_CTX * &fg_Context(void * &_pContext)
	{
		return reinterpret_cast<EVP_MD_CTX * &>(_pContext);
	}

	static EVP_MD_CTX const *fg_Context(void * const &_pContext)
	{
		return static_cast<EVP_MD_CTX const *>(_pContext);
	}

	template <EDigestType t_DigestType, mint t_DigestSize>
	TCHashImpl_BoringSSL<t_DigestType, t_DigestSize>::TCHashImpl_BoringSSL()
		: mp_pContext(nullptr)
	{
		fp_Init();
	}

	template <EDigestType t_DigestType, mint t_DigestSize>
	void TCHashImpl_BoringSSL<t_DigestType, t_DigestSize>::fp_Init()
	{
		auto &pContext = fg_Context(mp_pContext);
		pContext = EVP_MD_CTX_create();
		if (!pContext)
			DMibErrorCryptography(fg_GetExceptionStr("Failed to create digest context"));

		auto Cleanup = g_OnScopeExit / [&]
			{
				EVP_MD_CTX_destroy(pContext);
				pContext = nullptr;
			}
		;

		if (!EVP_DigestInit_ex(pContext, fg_GetDigest(t_DigestType), nullptr))
			DMibErrorCryptography(fg_GetExceptionStr("Failed to init digest"));

		Cleanup.f_Clear();
	}

	template <EDigestType t_DigestType, mint t_DigestSize>
	void TCHashImpl_BoringSSL<t_DigestType, t_DigestSize>::fp_Destroy()
	{
		auto &pContext = fg_Context(mp_pContext);
		if (pContext)
		{
			EVP_MD_CTX_destroy(pContext);
			pContext = nullptr;
		}
	}

	template <EDigestType t_DigestType, mint t_DigestSize>
	TCHashImpl_BoringSSL<t_DigestType, t_DigestSize>::~TCHashImpl_BoringSSL()
	{
		fp_Destroy();
	}

	template <EDigestType t_DigestType, mint t_DigestSize>
	TCHashImpl_BoringSSL<t_DigestType, t_DigestSize>::TCHashImpl_BoringSSL(TCHashImpl_BoringSSL const &_Other)
		: mp_pContext(nullptr)
	{
		auto pOtherContext = fg_Context(_Other.mp_pContext);
		if (!pOtherContext)
			return;

		fp_Init();

		auto &pContext = fg_Context(mp_pContext);

		if (!EVP_MD_CTX_copy_ex(pContext, pOtherContext))
			DMibErrorCryptography(fg_GetExceptionStr("Failed to copy digest context"));
	}

	template <EDigestType t_DigestType, mint t_DigestSize>
	TCHashImpl_BoringSSL<t_DigestType, t_DigestSize>::TCHashImpl_BoringSSL(TCHashImpl_BoringSSL &&_Other)
		: mp_pContext(fg_Exchange(_Other.mp_pContext, nullptr))
	{

	}

	template <EDigestType t_DigestType, mint t_DigestSize>
	auto TCHashImpl_BoringSSL<t_DigestType, t_DigestSize>::operator = (TCHashImpl_BoringSSL const &_Other) -> TCHashImpl_BoringSSL &
	{
		auto pOtherContext = fg_Context(_Other.mp_pContext);
		if (!pOtherContext)
		{
			fp_Destroy();
			return *this;
		}
		else if (!mp_pContext)
			fp_Init();

		auto &pContext = fg_Context(mp_pContext);

		if (!EVP_MD_CTX_copy_ex(pContext, pOtherContext))
			DMibErrorCryptography(fg_GetExceptionStr("Failed to copy digest context"));

		return *this;
	}

	template <EDigestType t_DigestType, mint t_DigestSize>
	auto TCHashImpl_BoringSSL<t_DigestType, t_DigestSize>::operator = (TCHashImpl_BoringSSL &&_Other) -> TCHashImpl_BoringSSL &
	{
		fp_Destroy();
		mp_pContext = fg_Exchange(_Other.mp_pContext, nullptr);
		return *this;
	}

	template <EDigestType t_DigestType, mint t_DigestSize>
	void TCHashImpl_BoringSSL<t_DigestType, t_DigestSize>::f_AddData(void const *_pData, mint _Len)
	{
		auto &pContext = fg_Context(mp_pContext);
		DMibFastCheck(pContext);

		if (!EVP_DigestUpdate(pContext, _pData, _Len))
			DMibErrorCryptography(fg_GetExceptionStr("Failed to update context"));
	}

	template <EDigestType t_DigestType, mint t_DigestSize>
	template <typename tf_CDigest>
	void TCHashImpl_BoringSSL<t_DigestType, t_DigestSize>::f_GetDigest(tf_CDigest &o_Digest) const
	{
		static_assert(t_DigestSize == tf_CDigest::mc_Size);
		auto Temp = *this;

		auto &pContext = fg_Context(Temp.mp_pContext);
		DMibFastCheck(pContext);
		DMibFastCheck(EVP_MD_CTX_size(pContext) == t_DigestSize);

		unsigned int Size;
		if (!EVP_DigestFinal_ex(pContext, o_Digest.f_GetData(), &Size))
			DMibErrorCryptography(fg_GetExceptionStr("Failed to finalize digest"));

		DMibFastCheck(Size == t_DigestSize);
	}
}
