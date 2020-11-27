
#include "Malterlib_Cryptography_RandomData.h"

namespace NMib::NCryptography
{
	void fg_GenerateRandomData(uint8 *_pData, mint _nBytes)
	{
		mint nUint32 = _nBytes / 4;
		for (mint i = 0; i < nUint32; ++i)
		{
			uint32 Random = NMisc::fg_GetRandomUnsigned();
			NMemory::fg_MemCopy(_pData + i*4, &Random, sizeof(Random));
		}
		for (mint i = nUint32*4; i < _nBytes; ++i)
			_pData[i] = NMisc::fg_GetRandomUnsigned();
	}
}
