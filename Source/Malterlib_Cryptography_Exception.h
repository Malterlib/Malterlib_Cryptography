// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Exception/Exception>

namespace NMib::NCryptography
{
	DMibImpErrorClassDefine(CExceptionCryptography, NException::CException);
#define DMibErrorCryptography(d_Description) DMibImpError(NMib::NCryptography::CExceptionCryptography, d_Description)

#ifndef DMibPNoShortCuts
#	define DErrorCryptography(d_Description) DMibErrorCryptography(d_Description)
#endif
}

#ifndef DMibPNoShortCuts
using namespace NMib::NCryptography;
#endif
