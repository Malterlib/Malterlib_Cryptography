// Copyright © 2015 Hansoft AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

#include "Malterlib_Cryptography_KeyDerivation.h"

namespace NMib::NCryptography::NPrivate
{
	void fg_DeriveKeyArgon2id
		(
			NStr::CStrSecure const &_Password
			, NContainer::CSecureByteVector const &_PasswordSalt
			, CKeyDerivationSettings_Argon2id const &_Settings
			, NContainer::CSecureByteVector &o_Key
		)
	;
}
