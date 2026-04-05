// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#if defined(DPlatformFamily_Windows) && defined(DArchitecture_x64)

struct CRegisterState
{
	__m128 m_XMM6;
	__m128 m_XMM7;
	__m128 m_XMM8;
	__m128 m_XMM9;
	__m128 m_XMM10;
	__m128 m_XMM11;
	__m128 m_XMM12;
	__m128 m_XMM13;
	__m128 m_XMM14;
	__m128 m_XMM15;

	uint64 m_RDI;
	uint64 m_RSI;
	uint64 m_RBX;
	uint64 m_RBP;

	uint64 m_R12;
	uint64 m_R13;
	uint64 m_R14;
	uint64 m_R15;
};

extern "C" void fg_Malterlib_Network_SSL_SaveRegisters_X86_64(CRegisterState *_pRegisters);
extern "C" void fg_Malterlib_Network_SSL_RestoreRegisters_X86_64(CRegisterState *_pRegisters);

namespace NMib::NCryptography::NBoringSSL
{
	struct COpenSSLBrokenRegistryHandlingScope
	{
		inline_always COpenSSLBrokenRegistryHandlingScope()
		{
			fg_Malterlib_Network_SSL_SaveRegisters_X86_64(&m_RegisterState);
		}
		inline_always ~COpenSSLBrokenRegistryHandlingScope()
		{
			fg_Malterlib_Network_SSL_RestoreRegisters_X86_64(&m_RegisterState);
		}

		DMibThreadLocalScopeDebugMember;
		CRegisterState m_RegisterState;
	};

	template <typename t_FToRun>
	struct TCRunProtectedRegistersHelper
	{
		TCRunProtectedRegistersHelper(t_FToRun &&_fToRun)
			: mp_fToRun(NMib::fg_Move(_fToRun))
		{

		}
		inline_never decltype(auto) f_Run()
		{
			COpenSSLBrokenRegistryHandlingScope ProtectionScope;
			return fp_Run();
		}
	private:

		inline_never decltype(auto) fp_Run()
		{
			return mp_fToRun();
		}

		t_FToRun &&mp_fToRun;
	};

	template <typename t_FToRun>
	decltype(auto) fg_RunProtectRegisters(t_FToRun &&_fToRun)
	{
		TCRunProtectedRegistersHelper<t_FToRun &&> RunHelper{NMib::fg_Move(_fToRun)};

		return RunHelper.f_Run();
	}
}

#else

namespace NMib::NCryptography::NBoringSSL
{
	template <typename t_FToRun>
	inline_always decltype(auto) fg_RunProtectRegisters(t_FToRun &&_fToRun)
	{
		return _fToRun();
	}
}

#endif
