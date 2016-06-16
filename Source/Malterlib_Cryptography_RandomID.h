
#pragma once

namespace NMib
{
	namespace NCryptography
	{
		NStr::CStr fg_RandomID();
		NStr::CStr fg_HighEntropyRandomID();
	}
}

#ifndef DMibPNoShortCuts
using namespace NMib::NCryptography;
#endif

