// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

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
