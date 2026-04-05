// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

namespace NMib::NCryptography
{
	enum EUniversallyUniqueIdentifierFormat
	{
		EUniversallyUniqueIdentifierFormat_Bare
		, EUniversallyUniqueIdentifierFormat_Registry
		, EUniversallyUniqueIdentifierFormat_AlphaNum
	};
	enum EUniversallyUniqueIdentifierGenerate
	{
		EUniversallyUniqueIdentifierGenerate_Secure
		, EUniversallyUniqueIdentifierGenerate_Random
		, EUniversallyUniqueIdentifierGenerate_StringHash
	};
	struct CUniversallyUniqueIdentifier
	{
		uint32 m_TimeLow = 0;
		uint16 m_TimeMid = 0;
		uint16 m_TimeHiAndVersion = 0;
		uint8 m_ClockSequenceHiAndReserved = 0;
		uint8 m_ClockSquenceLow = 0;
		uint8 m_Node[6] = {0};

		CUniversallyUniqueIdentifier
			(
				EUniversallyUniqueIdentifierGenerate _Generate
				, CUniversallyUniqueIdentifier const &_Namespace = CUniversallyUniqueIdentifier()
				, NStr::CStr const &_InData = NStr::CStr()
			)
		;
		CUniversallyUniqueIdentifier(NStr::CStr const &_RegistryFormat, EUniversallyUniqueIdentifierFormat _Format = EUniversallyUniqueIdentifierFormat_Registry);
		constexpr CUniversallyUniqueIdentifier
			(
				uint32 _TimeLow
				, uint16 _TimeMid
				, uint16 _TimeHiAndVersion
				, uint16 _ClockSequence
				, uint64 _Node
			)
		;
		constexpr ~CUniversallyUniqueIdentifier();
		NStr::CStr f_GetAsString(EUniversallyUniqueIdentifierFormat _Format = EUniversallyUniqueIdentifierFormat_Registry);
		NStr::CFStr256 f_GetAsStaticString(EUniversallyUniqueIdentifierFormat _Format = EUniversallyUniqueIdentifierFormat_Registry);

		static CUniversallyUniqueIdentifier fs_Empty();

		auto operator <=> (CUniversallyUniqueIdentifier const &_Right) const noexcept = default;

	private:
		constexpr CUniversallyUniqueIdentifier();
		void fp_CreateFromSHA1(CUniversallyUniqueIdentifier const &_Namespace, void const *_pData, umint _DataLen);
		void fp_CreateFromMD5(CUniversallyUniqueIdentifier const &_Namespace, void const *_pData, umint _DataLen);
		void fp_CreateFromHash(uint8 *_pHash, int32 _Version);

	};

	NStr::CStr fg_GetRandomUuidString(EUniversallyUniqueIdentifierFormat _Format = EUniversallyUniqueIdentifierFormat_AlphaNum);
	NStr::CStr fg_GetSecureUuidString(EUniversallyUniqueIdentifierFormat _Format = EUniversallyUniqueIdentifierFormat_AlphaNum);
	NStr::CStr fg_GetHashedUuidString
		(
			NStr::CStr const &_ToHash
			, CUniversallyUniqueIdentifier const &_Namespace
			, EUniversallyUniqueIdentifierFormat _Format = EUniversallyUniqueIdentifierFormat_AlphaNum
		)
	;
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NCryptography;
#endif

#include "Malterlib_Cryptography_UUID.hpp"
