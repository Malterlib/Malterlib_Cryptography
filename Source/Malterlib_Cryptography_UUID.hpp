// Copyright © 2022 Favro Holding AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

namespace NMib::NCryptography
{
	constexpr CUniversallyUniqueIdentifier::CUniversallyUniqueIdentifier() = default;

	constexpr CUniversallyUniqueIdentifier::~CUniversallyUniqueIdentifier()
	{
		if (!std::is_constant_evaluated())
			NMemory::fg_SecureMemClear(*this);
	}

	constexpr CUniversallyUniqueIdentifier::CUniversallyUniqueIdentifier
		(
			uint32 _TimeLow
			, uint16 _TimeMid
			, uint16 _TimeHiAndVersion
			, uint16 _ClockSequence
			, uint64 _Node
			, EUniversallyUniqueIdentifierFormat _Format
		)
		: m_TimeLow(_TimeLow)
		, m_TimeMid(_TimeMid)
		, m_TimeHiAndVersion(_TimeHiAndVersion)
		, m_ClockSequenceHiAndReserved(_ClockSequence >> 8)
		, m_ClockSquenceLow(_ClockSequence & uint8(0xff))
		, m_Node
		{
			uint8((_Node >> 8*5) & uint8(0xff))
			, uint8((_Node >> 8*4) & uint8(0xff))
			, uint8((_Node >> 8*3) & uint8(0xff))
			, uint8((_Node >> 8*2) & uint8(0xff))
			, uint8((_Node >> 8*1) & uint8(0xff))
			, uint8((_Node >> 8*0) & uint8(0xff))
		}
	{
	}
}
