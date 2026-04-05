// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

namespace NMib::NCryptography
{
	template <typename tf_CContainer>
	NStr::CStr fg_RandomID(tf_CContainer &_AssociativeContainer, umint _nCharacters)
	{
		NStr::CStr RandomID = fg_RandomID(_nCharacters);
		while (_AssociativeContainer.f_FindEqual(RandomID))
			RandomID = fg_RandomID(_nCharacters);

		return RandomID;
	}

	template <typename tf_CContainer>
	NStr::CStr fg_FastRandomID(tf_CContainer &_AssociativeContainer, umint _nCharacters)
	{
		NStr::CStr RandomID = fg_FastRandomID(_nCharacters);
		while (_AssociativeContainer.f_FindEqual(RandomID))
			RandomID = fg_FastRandomID(_nCharacters);

		return RandomID;
	}
}
