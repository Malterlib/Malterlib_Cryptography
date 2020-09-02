
#pragma once

namespace NMib::NCryptography
{
	template <typename tf_CContainer>
	NStr::CStr fg_RandomID(tf_CContainer &_AssociativeContainer, mint _nCharacters)
	{
		NStr::CStr RandomID = fg_RandomID(_nCharacters);
		while (_AssociativeContainer.f_FindEqual(RandomID))
			RandomID = fg_RandomID(_nCharacters);

		return RandomID;
	}
}
