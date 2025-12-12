
#pragma once

namespace NMib::NCryptography
{
	// Secure random IDs (ChaCha20-based, cryptographically secure)
	NStr::CStr fg_RandomID(mint _nCharacters = 17);
	template <typename tf_CContainer>
	NStr::CStr fg_RandomID(tf_CContainer &_AssociativeContainer, mint _nCharacters = 17);
	NStr::CStrSecure fg_RandomID(ch8 const *_pCharacters, mint _Len = 32);

	// High entropy random IDs (OS CSPRNG per byte, slower but maximum entropy)
	NStr::CStr fg_HighEntropyRandomID(mint _nCharacters = 17);
	NStr::CStrSecure fg_HighEntropyRandomID(ch8 const *_pCharacters, mint _Len = 32);

	// Fast random IDs (XorShift-based, NOT cryptographically secure - use for non-security purposes)
	NStr::CStr fg_FastRandomID(mint _nCharacters = 17);
	template <typename tf_CContainer>
	NStr::CStr fg_FastRandomID(tf_CContainer &_AssociativeContainer, mint _nCharacters = 17);
	NStr::CStrSecure fg_FastRandomID(ch8 const *_pCharacters, mint _Len = 32);
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif

#include "Malterlib_Cryptography_RandomID.hpp"
