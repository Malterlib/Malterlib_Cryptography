
#include "Malterlib_Cryptography_RandomID.h"

namespace NMib
{
	namespace NCryptography
	{
		namespace
		{
			ch8 g_UnmistakableChars[] = "23456789ABCDEFGHJKLMNPQRSTWXYZabcdefghijkmnopqrstuvwxyz";
		}

		NStr::CStr fg_RandomID()
		{
			const mint c_nCharsInRandomID = 17;
			const mint c_nChars = sizeof(g_UnmistakableChars) / sizeof(g_UnmistakableChars[0]) - 1;
			const mint c_BufferSize = ((c_nCharsInRandomID + 3) / 4) * 4;
			uint8 RandomData[c_BufferSize];

			for (mint i = 0; i < sizeof(RandomData) / 4; ++i)
				*((uint32 *)(RandomData + i*4)) = NMisc::fg_GetRandomUnsigned();

			NStr::CStr Return;

			for (mint i = 0; i < c_nCharsInRandomID; ++i)
				Return.f_AddChar(g_UnmistakableChars[RandomData[i] % c_nChars]);

			return Return;
		}
		
		NStr::CStr fg_HighEntropyRandomID()
		{
			const mint c_nCharsInRandomID = 17;
			const mint c_nChars = sizeof(g_UnmistakableChars) / sizeof(g_UnmistakableChars[0]) - 1;
			const mint c_BufferSize = ((c_nCharsInRandomID + 3) / 4) * 4;
			uint8 RandomData[c_BufferSize];
			
			NSys::fg_Security_GenerateHighEntropyData(RandomData, c_BufferSize);

			NStr::CStr Return;

			for (mint i = 0; i < c_nCharsInRandomID; ++i)
				Return.f_AddChar(g_UnmistakableChars[RandomData[i] % c_nChars]);

			return Return;
		}
	}
}

