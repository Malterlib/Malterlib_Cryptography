
#pragma once

namespace NMib::NCryptography
{
	template <typename tf_CContainer>
	NStr::CStr fg_RandomID(tf_CContainer &_AssociativeContainer)
	{
		NStr::CStr RandomID = fg_RandomID();
		while (_AssociativeContainer.f_FindEqual(RandomID))
			RandomID = fg_RandomID();

		return RandomID;
	}
}
