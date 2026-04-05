// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Exception/Exception>

namespace NMib::NCryptography
{
	DMibImpErrorClassDefine(CExceptionCryptography, NException::CException);
#	define DMibErrorCryptography(_Description) DMibImpError(NMib::NCryptography::CExceptionCryptography, _Description)

#	ifndef DMibPNoShortCuts
#		define DErrorCryptography(_Description) DMibErrorCryptography(_Description)
#	endif
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
