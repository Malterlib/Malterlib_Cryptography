
#include "Malterlib_Cryptography_RandomID.h"

namespace NMib::NCryptography
{
	namespace
	{
		ch8 g_UnmistakableChars[] = "23456789ABCDEFGHJKLMNPQRSTWXYZabcdefghijkmnopqrstuvwxyz";
	}

	NStr::CStr fg_RandomID(mint _nCharacters)
	{
		const mint c_nChars = sizeof(g_UnmistakableChars) / sizeof(g_UnmistakableChars[0]) - 1;
		const mint c_BufferSize = ((_nCharacters + 3) / 4) * 4;
		uint8 RandomData[c_BufferSize];

		for (mint i = 0; i < sizeof(RandomData) / 4; ++i)
			*((uint32 *)(RandomData + i*4)) = NMisc::fg_GetRandomUnsigned();

		NStr::CStr Return;

		for (mint i = 0; i < _nCharacters; ++i)
			Return.f_AddChar(g_UnmistakableChars[RandomData[i] % c_nChars]);

		return Return;
	}

	NStr::CStr fg_HighEntropyRandomID(mint _nCharacters)
	{
		const mint c_nChars = sizeof(g_UnmistakableChars) / sizeof(g_UnmistakableChars[0]) - 1;
		const mint c_BufferSize = ((_nCharacters + 3) / 4) * 4;
		uint8 RandomData[c_BufferSize];

		NSys::fg_Security_GenerateHighEntropyData(RandomData, c_BufferSize);

		NStr::CStr Return;

		for (mint i = 0; i < _nCharacters; ++i)
			Return.f_AddChar(g_UnmistakableChars[RandomData[i] % c_nChars]);

		return Return;
	}

	NStr::CStrSecure fg_RandomID(ch8 const *_pCharacters, mint _Len)
	{
		mint nCharsInRandomID = _Len;
		mint nChars = NStr::fg_StrLen(_pCharacters);
		mint BufferSize = ((nCharsInRandomID + 3) / 4) * 4;
		NContainer::CSecureByteVector RandomData;
		RandomData.f_SetLen(BufferSize);
		uint8 *pRandomData = RandomData.f_GetArray();

		for (mint i = 0; i < sizeof(RandomData) / 4; ++i)
			*((uint32 *)(pRandomData + i*4)) = NMisc::fg_GetRandomUnsigned();

		NStr::CStrSecure Return;

		for (mint i = 0; i < nCharsInRandomID; ++i)
			Return.f_AddChar(_pCharacters[RandomData[i] % nChars]);

		return Return;
	}

	NStr::CStrSecure fg_HighEntropyRandomID(ch8 const *_pCharacters, mint _Len)
	{
		mint nCharsInRandomID = _Len;
		mint nChars = NStr::fg_StrLen(_pCharacters);
		mint BufferSize = ((nCharsInRandomID + 3) / 4) * 4;
		NContainer::CSecureByteVector RandomData;
		RandomData.f_SetLen(BufferSize);
		uint8 *pRandomData = RandomData.f_GetArray();

		NSys::fg_Security_GenerateHighEntropyData(pRandomData, BufferSize);

		NStr::CStrSecure Return;

		for (mint i = 0; i < nCharsInRandomID; ++i)
			Return.f_AddChar(_pCharacters[RandomData[i] % nChars]);

		return Return;
	}
}
