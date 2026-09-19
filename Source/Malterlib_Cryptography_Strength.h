// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Core/Core>

namespace NMib::NCryptography
{
	enum class ECryptoStrength : uint16
	{
		mc_Compatible = 0,
		mc_EquivalentSymmetric128bit = 128,
		mc_EquivalentSymmetric192bit = 192,
		mc_EquivalentSymmetric256bit = 256,
	};
}
