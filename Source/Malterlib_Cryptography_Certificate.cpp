// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Cryptography_Certificate.h"

#include <Mib/Cryptography/BoringSSL>

namespace NMib::NCryptography
{
	using namespace NBoringSSL;

	void CCertificateOptions::f_MakeCA()
	{
		f_AddExtension_BasicConstraints(true);
		f_AddExtension_KeyUsage(EKeyUsage_CertificateSign | EKeyUsage_CRLSign);
	}

	void CCertificateOptions::f_AddExtension_BasicConstraints(bool _bCA, bool _bCritical)
	{
		using namespace NMib::NStr;
		auto &Extension = m_Extensions["2.5.29.19"].f_Insert();
		Extension.m_bCritical = _bCritical;
		Extension.m_Value = "CA:{}"_f << (_bCA ? "TRUE" : "FALSE");
	}

	void CCertificateSignOptions::f_AddExtension_SubjectKeyIdentifier(bool _bCritical)
	{
		auto &Extension = m_Extensions["2.5.29.14"].f_Insert();
		Extension.m_bCritical = _bCritical;
		Extension.m_Value = "hash";
	}

	void CCertificateSignOptions::f_AddExtension_AuthorityKeyIdentifier(bool _bCritical)
	{
		using namespace NStr;
		auto &Extension = m_Extensions["2.5.29.35"].f_Insert();
		Extension.m_Value = "keyid:always";
	}

	void CCertificateOptions::f_AddExtension_KeyUsage(EKeyUsage _KeyUsage, bool _bCritical)
	{
		NStr::CStr KeyUsage;
		if (_KeyUsage & EKeyUsage_DigitalSignature)
			fg_AddStrSep(KeyUsage, "digitalSignature", ",");
		if (_KeyUsage & EKeyUsage_NonRepudiation)
			fg_AddStrSep(KeyUsage, "nonRepudiation", ",");
		if (_KeyUsage & EKeyUsage_KeyEncipherment)
			fg_AddStrSep(KeyUsage, "keyEncipherment", ",");
		if (_KeyUsage & EKeyUsage_DataEncipherment)
			fg_AddStrSep(KeyUsage, "dataEncipherment", ",");
		if (_KeyUsage & EKeyUsage_KeyAgreement)
			fg_AddStrSep(KeyUsage, "keyAgreement", ",");
		if (_KeyUsage & EKeyUsage_CertificateSign)
			fg_AddStrSep(KeyUsage, "keyCertSign", ",");
		if (_KeyUsage & EKeyUsage_CRLSign)
			fg_AddStrSep(KeyUsage, "cRLSign", ",");
		if (_KeyUsage & EKeyUsage_EncipherOnly)
			fg_AddStrSep(KeyUsage, "encipherOnly", ",");
		if (_KeyUsage & EKeyUsage_DecipherOnly)
			fg_AddStrSep(KeyUsage, "decipherOnly", ",");

		auto &Extension = m_Extensions["2.5.29.15"].f_Insert();
		Extension.m_bCritical = _bCritical;
		Extension.m_Value = KeyUsage;
	}

	void CCertificateOptions::f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage _KeyUsage, bool _bCritical)
	{
		NStr::CStr KeyUsage;
		if (_KeyUsage & EExtendedKeyUsage_ServerAuth)
			fg_AddStrSep(KeyUsage, "serverAuth", ",");
		if (_KeyUsage & EExtendedKeyUsage_ClientAuth)
			fg_AddStrSep(KeyUsage, "clientAuth", ",");
		if (_KeyUsage & EExtendedKeyUsage_CodeSigning)
			fg_AddStrSep(KeyUsage, "codeSigning", ",");
		if (_KeyUsage & EExtendedKeyUsage_EmailProtection)
			fg_AddStrSep(KeyUsage, "emailProtection", ",");
		if (_KeyUsage & EExtendedKeyUsage_Timestamping)
			fg_AddStrSep(KeyUsage, "timeStamping", ",");

		auto &Extension = m_Extensions["2.5.29.37"].f_Insert();
		Extension.m_bCritical = _bCritical;
		Extension.m_Value = KeyUsage;
	}

	void CCertificate::fs_RegisterExtension(NStr::CStr const &_OID, NStr::CStr const &_ShortName, NStr::CStr const &_LongName)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					OBJ_create(_OID, _ShortName, _LongName);
				}
			)
		;
	}
}
