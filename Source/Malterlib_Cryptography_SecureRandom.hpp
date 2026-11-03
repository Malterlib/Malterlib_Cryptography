// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

namespace NMib::NCryptography
{
	template <typename tf_CInt>
	tf_CInt CSecureRandom::f_GetValue()
	{
		tf_CInt Return;
		f_GetBytes((uint8 *)&Return, sizeof(Return));
		return Return;
	}
}
