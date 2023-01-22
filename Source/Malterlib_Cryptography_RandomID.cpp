
#include "Malterlib_Cryptography_RandomID.h"
#include <Mib/String/Appender>

namespace NMib::NCryptography
{
	namespace
	{
		ch8 g_UnmistakableChars[] = "23456789ABCDEFGHJKLMNPQRSTWXYZabcdefghijkmnopqrstuvwxyz";
		constexpr mint gc_nChars = sizeof(g_UnmistakableChars) / sizeof(g_UnmistakableChars[0]) - 1;

		template
		<
			mint t_nBytesCache = 4
			, auto t_fNewBytes = [](uint8 *o_pBytes) -> void
			{
				auto Values = NMisc::fg_GetRandomUnsigned();
				o_pBytes[0] = Values & 0xff;
				o_pBytes[1] = (Values >> 8) & 0xff;
				o_pBytes[2] = (Values >> 16) & 0xff;
				o_pBytes[3] = (Values >> 24) & 0xff;
			}
		>
		struct TCUniformIntDistribution
		{
			TCUniformIntDistribution(uint8 _Max)
				: m_Max(_Max)
				, m_Mask(fg_RoundPowerOfTwoUp(_Max) - 1)
			{
			}

			~TCUniformIntDistribution()
			{
				NMemory::fg_SecureMemClear(m_Bytes);
			}

			void f_NewBytes()
			{
				t_fNewBytes(m_Bytes);
				m_iByte = 0;
			}

			uint8 operator ()()
			{
				while (true)
				{
					if (m_iByte == t_nBytesCache)
						f_NewBytes();

					auto Value = m_Bytes[m_iByte++] & m_Mask;
					if (Value < m_Max)
						return Value;
				}
			}

			uint8 m_Bytes[t_nBytesCache];
			mint m_iByte = t_nBytesCache;
			uint8 m_Max;
			uint8 m_Mask;
		};

		using CUniformIntDistribution = TCUniformIntDistribution<>;
		using CUniformIntDistributionHighEntropy = TCUniformIntDistribution
			<
				8
				, [](uint8 *o_pBytes) -> void
				{
					NSys::fg_Security_GenerateHighEntropyData(o_pBytes, 8);
				}
			>
		;
	}

	NStr::CStr fg_RandomID(mint _Len)
	{
		NStr::CStr Return;
		{
			NStr::CStr::CAppender Appender(Return);

			CUniformIntDistribution RandomDistribution(gc_nChars);
			for (mint i = 0; i < _Len; ++i)
				Appender += g_UnmistakableChars[RandomDistribution()];
		}

		return Return;
	}

	NStr::CStr fg_HighEntropyRandomID(mint _Len)
	{
		NStr::CStr Return;
		{
			NStr::CStr::CAppender Appender(Return);

			CUniformIntDistributionHighEntropy RandomDistribution(gc_nChars);
			for (mint i = 0; i < _Len; ++i)
				Appender += g_UnmistakableChars[RandomDistribution()];
		}

		return Return;
	}

	NStr::CStrSecure fg_RandomID(ch8 const *_pCharacters, mint _Len)
	{
		mint nChars = NStr::fg_StrLen(_pCharacters);
		DMibFastCheck(nChars > 0);

		NStr::CStrSecure Return;
		{
			NStr::CStrSecure::CAppender Appender(Return);

			CUniformIntDistribution RandomDistribution(nChars);
			for (mint i = 0; i < _Len; ++i)
				Appender += _pCharacters[RandomDistribution()];
		}

		return Return;
	}

	NStr::CStrSecure fg_HighEntropyRandomID(ch8 const *_pCharacters, mint _Len)
	{
		mint nChars = NStr::fg_StrLen(_pCharacters);
		DMibFastCheck(nChars > 0);

		NStr::CStrSecure Return;
		{
			NStr::CStrSecure::CAppender Appender(Return);

			CUniformIntDistributionHighEntropy RandomDistribution(nChars);
			for (mint i = 0; i < _Len; ++i)
				Appender += _pCharacters[RandomDistribution()];
		}

		return Return;
	}
}
