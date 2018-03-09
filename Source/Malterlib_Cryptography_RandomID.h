
#pragma once

namespace NMib
{
	namespace NCryptography
	{
		NStr::CStr fg_RandomID();
		NStr::CStr fg_HighEntropyRandomID();
		NStr::CStrSecure fg_RandomID(ch8 const *_pCharacters, mint _Len = 32);
		NStr::CStrSecure fg_HighEntropyRandomID(ch8 const *_pCharacters, mint _Len = 32);
	}
}

#ifndef DMibPNoShortCuts
using namespace NMib::NCryptography;
#endif

