// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#if defined(DPlatformFamily_Windows) && defined(DArchitecture_x64)

namespace NMib::NCryptography::NBoringSSL
{
	inline_always COpenSSLBrokenRegistryHandlingScope::COpenSSLBrokenRegistryHandlingScope()
	{
		fg_Malterlib_Network_SSL_SaveRegisters_X86_64(&m_RegisterState);
	}

	inline_always COpenSSLBrokenRegistryHandlingScope::~COpenSSLBrokenRegistryHandlingScope()
	{
		fg_Malterlib_Network_SSL_RestoreRegisters_X86_64(&m_RegisterState);
	}

	template <typename t_FToRun>
	TCRunProtectedRegistersHelper<t_FToRun>::TCRunProtectedRegistersHelper(t_FToRun &&_fToRun)
		: mp_fToRun(NMib::fg_Move(_fToRun))
	{
	}

	template <typename t_FToRun>
	inline_never decltype(auto) TCRunProtectedRegistersHelper<t_FToRun>::f_Run()
	{
		COpenSSLBrokenRegistryHandlingScope ProtectionScope;
		return fp_Run();
	}

	template <typename t_FToRun>
	inline_never decltype(auto) TCRunProtectedRegistersHelper<t_FToRun>::fp_Run()
	{
		return mp_fToRun();
	}

	template <typename tf_FToRun>
	decltype(auto) fg_RunProtectRegisters(tf_FToRun &&_fToRun)
	{
		TCRunProtectedRegistersHelper<tf_FToRun &&> RunHelper{NMib::fg_Move(_fToRun)};

		return RunHelper.f_Run();
	}
}

#else

namespace NMib::NCryptography::NBoringSSL
{
	template <typename tf_FToRun>
	inline_always decltype(auto) fg_RunProtectRegisters(tf_FToRun &&_fToRun)
	{
		return _fToRun();
	}
}

#endif
