// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

namespace NMib::NCryptography
{
	void fg_GenerateRandomData(uint8 *_pData, umint _nBytes);
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
