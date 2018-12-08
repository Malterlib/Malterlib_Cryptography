
#pragma once

namespace NMib::NCryptography
{
	void fg_GenerateRandomData(uint8 *_pData, mint _nBytes);
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
