// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

namespace NMib
{
	namespace NDataProcessing
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
			uint32 m_TimeLow;
			uint16 m_TimeMid;
			uint16 m_TimeHiAndVersion;
			uint8 m_ClockSequenceHiAndReserved;
			uint8 m_ClockSquenceLow;
			uint8 m_Node[6];

			CUniversallyUniqueIdentifier
				(
					EUniversallyUniqueIdentifierGenerate _Generate
					, CUniversallyUniqueIdentifier const &_Namespace = CUniversallyUniqueIdentifier()
					, NStr::CStr const &_InData = NStr::CStr()
				)
			;
			CUniversallyUniqueIdentifier(NStr::CStr const &_RegistryFormat, EUniversallyUniqueIdentifierFormat _Format = EUniversallyUniqueIdentifierFormat_Registry);
			NStr::CStr f_GetAsString(EUniversallyUniqueIdentifierFormat _Format = EUniversallyUniqueIdentifierFormat_Registry);
			NStr::CFStr256 f_GetAsStaticString(EUniversallyUniqueIdentifierFormat _Format = EUniversallyUniqueIdentifierFormat_Registry);
			bool operator == (CUniversallyUniqueIdentifier const &_Right) const;
			bool operator < (CUniversallyUniqueIdentifier const &_Right) const;

		private:
			CUniversallyUniqueIdentifier();
			void fp_CreateFromSHA1(CUniversallyUniqueIdentifier const &_Namespace, void const *_pData, mint _DataLen);
			void fp_CreateFromMD5(CUniversallyUniqueIdentifier const &_Namespace, void const *_pData, mint _DataLen);
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
}

#ifndef DMibPNoShortCuts
using namespace NMib::NDataProcessing;
#endif
