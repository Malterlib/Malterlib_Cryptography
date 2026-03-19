
#pragma once

namespace NMib::NCryptography
{
	void fg_GenerateRandomData(uint8 *_pData, umint _nBytes);
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif
