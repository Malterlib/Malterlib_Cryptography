// Copyright © 2015 Hansoft AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include "Malterlib_Cryptography_UUID.h"
#include <Mib/Cryptography/Hashes/SHA>

namespace NMib::NCryptography
{
	CUniversallyUniqueIdentifier::CUniversallyUniqueIdentifier
		(
			EUniversallyUniqueIdentifierGenerate _Generate
			, CUniversallyUniqueIdentifier const &_Namespace
			, NStr::CStr const &_InData
		)
	{
		switch (_Generate)
		{
		case EUniversallyUniqueIdentifierGenerate_Secure:
			NMib::NSys::fg_System_GenerateUUID(*this);
			break;
		case EUniversallyUniqueIdentifierGenerate_Random:
			{
				uint32 Random = NMisc::fg_GetRandomUnsigned();
				NMemory::fg_MemCopy((uint8 *)this, &Random, 4);
				Random = NMisc::fg_GetRandomUnsigned();
				NMemory::fg_MemCopy((uint8 *)this + 4, &Random, 4);
				Random = NMisc::fg_GetRandomUnsigned();
				NMemory::fg_MemCopy((uint8 *)this + 8, &Random, 4);
				Random = NMisc::fg_GetRandomUnsigned();
				NMemory::fg_MemCopy((uint8 *)this + 12, &Random, 4);

				m_TimeHiAndVersion &= 0x0FFF;
				m_TimeHiAndVersion |= ((4) << 12);
				m_ClockSequenceHiAndReserved &= 0x3F;
				m_ClockSequenceHiAndReserved |= 0x80;
			}
			break;
		case EUniversallyUniqueIdentifierGenerate_StringHash:
			{
				NStr::CStr Value = _InData;
				fp_CreateFromSHA1(_Namespace, Value.f_GetStr(), Value.f_GetLen());
			}
			break;
		}
	}

	CUniversallyUniqueIdentifier::CUniversallyUniqueIdentifier(NStr::CStr const &_RegistryFormat, EUniversallyUniqueIdentifierFormat _Format)
	{
		uint16 ClockSequence;
		uint64 Node;
		aint nParsedArgs = 0;

		char const* pFormat = nullptr;
		switch(_Format)
		{
			default:
			case EUniversallyUniqueIdentifierFormat_Registry:
				pFormat = "{{{nfh}-{nfh}-{nfh}-{nfh}-{nfh}}";
				break;
			case EUniversallyUniqueIdentifierFormat_Bare:
				pFormat = "{nfh}-{nfh}-{nfh}-{nfh}-{nfh}";
				break;
			case EUniversallyUniqueIdentifierFormat_AlphaNum:
				DMibError("EUniversallyUniqueIdentifierFormat_AlphaNum parsing of GUID not supported");
				break;
		}

		(
			NStr::CStr::CParse
			(
				pFormat
			) >> m_TimeLow >> m_TimeMid >> m_TimeHiAndVersion >> ClockSequence >> Node
		).f_Parse(_RegistryFormat, nParsedArgs);

		if (nParsedArgs != 5)
			DMibError("Failed to parse GUID");

		m_ClockSequenceHiAndReserved = ClockSequence >> 8;
		m_ClockSquenceLow = ClockSequence & uint8(0xff);

		m_Node[0] = (Node >> 8*5) & uint8(0xff);
		m_Node[1] = (Node >> 8*4) & uint8(0xff);
		m_Node[2] = (Node >> 8*3) & uint8(0xff);
		m_Node[3] = (Node >> 8*2) & uint8(0xff);
		m_Node[4] = (Node >> 8*1) & uint8(0xff);
		m_Node[5] = (Node >> 8*0) & uint8(0xff);
	}

	CUniversallyUniqueIdentifier CUniversallyUniqueIdentifier::fs_Empty()
	{
		return {};
	}

	template <typename tf_CStrType>
	static tf_CStrType fg_GetUUIDAsString(CUniversallyUniqueIdentifier &_UUID, EUniversallyUniqueIdentifierFormat _Format)
	{
		char const* pFormat = nullptr;
		switch(_Format)
		{
			default:
			case EUniversallyUniqueIdentifierFormat_Registry:
				pFormat = "{{{nfh,nc,sj8,sf0}-{nfh,nc,sj4,sf0}-{nfh,nc,sj4,sf0}-{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}-{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}}";
				break;
			case EUniversallyUniqueIdentifierFormat_Bare:
				pFormat = "{nfh,nc,sj8,sf0}-{nfh,nc,sj4,sf0}-{nfh,nc,sj4,sf0}-{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}-{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}";
				break;
			case EUniversallyUniqueIdentifierFormat_AlphaNum:
				pFormat = "{nfh,nc,sj8,sf0}{nfh,nc,sj4,sf0}{nfh,nc,sj4,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}{nfh,nc,sj2,sf0}";
				break;
		}

		return typename tf_CStrType::CFormat
			(
				pFormat
			)
			<< _UUID.m_TimeLow
			<< _UUID.m_TimeMid
			<< _UUID.m_TimeHiAndVersion
			<< _UUID.m_ClockSequenceHiAndReserved
			<< _UUID.m_ClockSquenceLow
			<< _UUID.m_Node[0]
			<< _UUID.m_Node[1]
			<< _UUID.m_Node[2]
			<< _UUID.m_Node[3]
			<< _UUID.m_Node[4]
			<< _UUID.m_Node[5]
		;
	}

	NStr::CStr CUniversallyUniqueIdentifier::f_GetAsString(EUniversallyUniqueIdentifierFormat _Format)
	{
		return fg_GetUUIDAsString<NStr::CStr>(*this, _Format);
	}
	
	NStr::CFStr256 CUniversallyUniqueIdentifier::f_GetAsStaticString(EUniversallyUniqueIdentifierFormat _Format)
	{
		return fg_GetUUIDAsString<NStr::CFStr256>(*this, _Format);
	}

	void CUniversallyUniqueIdentifier::fp_CreateFromSHA1(CUniversallyUniqueIdentifier const &_Namespace, void const *_pData, mint _DataLen)
	{
		CUniversallyUniqueIdentifier BigEndianNamespace = _Namespace;

		BigEndianNamespace.m_TimeLow = fg_ByteSwapBE(BigEndianNamespace.m_TimeLow);
		BigEndianNamespace.m_TimeMid = fg_ByteSwapBE(BigEndianNamespace.m_TimeMid);
		BigEndianNamespace.m_TimeHiAndVersion = fg_ByteSwapBE(BigEndianNamespace.m_TimeHiAndVersion);

		NCryptography::CHash_SHA1 Hash;
		Hash.f_AddData(_pData, _DataLen);
		NCryptography::CHashDigest_SHA1 Digest = Hash;

		fp_CreateFromHash(Digest.f_GetData(), 5);
	}

	void CUniversallyUniqueIdentifier::fp_CreateFromMD5(CUniversallyUniqueIdentifier const &_Namespace, void const *_pData, mint _DataLen)
	{
		CUniversallyUniqueIdentifier BigEndianNamespace = _Namespace;

		BigEndianNamespace.m_TimeLow = fg_ByteSwapBE(BigEndianNamespace.m_TimeLow);
		BigEndianNamespace.m_TimeMid = fg_ByteSwapBE(BigEndianNamespace.m_TimeMid);
		BigEndianNamespace.m_TimeHiAndVersion = fg_ByteSwapBE(BigEndianNamespace.m_TimeHiAndVersion);

		NCryptography::CHash_SHA1 Hash;
		Hash.f_AddData(_pData, _DataLen);
		NCryptography::CHashDigest_SHA1 Digest = Hash;

		fp_CreateFromHash(Digest.f_GetData(), 3);
	}

	void CUniversallyUniqueIdentifier::fp_CreateFromHash(uint8 *_pHash, int32 _Version)
	{
		static_assert(sizeof(*this) == 16, "Strung packing not correct");

		NMemory::fg_MemCopy(this, _pHash, sizeof(*this));

		m_TimeLow = fg_ByteSwapBE(m_TimeLow);
		m_TimeMid = fg_ByteSwapBE(m_TimeMid);
		m_TimeHiAndVersion = fg_ByteSwapBE(m_TimeHiAndVersion);

		m_TimeHiAndVersion &= 0x0FFF;
		m_TimeHiAndVersion |= (_Version << 12);
		m_ClockSequenceHiAndReserved &= 0x3F;
		m_ClockSequenceHiAndReserved |= 0x80;
	}

	NStr::CStr fg_GetRandomUuidString(EUniversallyUniqueIdentifierFormat _Format)
	{
		CUniversallyUniqueIdentifier UUID(EUniversallyUniqueIdentifierGenerate_Random);
		return UUID.f_GetAsString(_Format);
	}
	NStr::CStr fg_GetSecureUuidString(EUniversallyUniqueIdentifierFormat _Format)
	{
		CUniversallyUniqueIdentifier UUID(EUniversallyUniqueIdentifierGenerate_Secure);
		return UUID.f_GetAsString(_Format);
	}

	NStr::CStr fg_GetHashedUuidString(NStr::CStr const &_ToHash, CUniversallyUniqueIdentifier const &_Namespace, EUniversallyUniqueIdentifierFormat _Format)
	{
		CUniversallyUniqueIdentifier UUID(EUniversallyUniqueIdentifierGenerate_StringHash, _Namespace, _ToHash);
		return UUID.f_GetAsString(_Format);
	}
}
