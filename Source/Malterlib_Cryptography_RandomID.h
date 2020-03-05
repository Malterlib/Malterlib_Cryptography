
#pragma once

namespace NMib::NCryptography
{
	NStr::CStr fg_RandomID();
	template <typename tf_CContainer>
	NStr::CStr fg_RandomID(tf_CContainer &_AssociativeContainer);
	NStr::CStr fg_HighEntropyRandomID();
	NStr::CStrSecure fg_RandomID(ch8 const *_pCharacters, mint _Len = 32);
	NStr::CStrSecure fg_HighEntropyRandomID(ch8 const *_pCharacters, mint _Len = 32);
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif

#include "Malterlib_Cryptography_RandomID.hpp"
