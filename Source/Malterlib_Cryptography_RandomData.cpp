
#include "Malterlib_Cryptography_RandomData.h"
#include <Mib/Cryptography/SecureRandom>

namespace NMib::NCryptography
{
	void fg_GenerateRandomData(uint8 *_pData, mint _nBytes)
	{
		NMisc::fg_SecureRandomThreadLocal().f_GetBytes(_pData, _nBytes);
	}
}
