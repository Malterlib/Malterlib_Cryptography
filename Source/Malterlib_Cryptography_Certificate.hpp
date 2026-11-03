// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

namespace NMib::NCryptography
{
	template <typename tf_CFormatInto>
	void CCertificateExtension::f_Format(tf_CFormatInto &o_FormatInto) const
	{
		o_FormatInto += typename tf_CFormatInto::CFormat("{}{}") << m_Value << (m_bCritical ? " - critical" : "");
	}
}
