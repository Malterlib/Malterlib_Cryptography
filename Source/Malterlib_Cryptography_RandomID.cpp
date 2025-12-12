
#include "Malterlib_Cryptography_RandomID.h"
#include <Mib/String/Appender>
#include <Mib/Cryptography/SecureRandom>

namespace NMib::NCryptography
{
	namespace
	{
		constexpr ch8 gc_UnmistakableChars[] = "23456789ABCDEFGHJKLMNPQRSTWXYZabcdefghijkmnopqrstuvwxyz";
		constexpr mint gc_nChars = fg_ArraySize(gc_UnmistakableChars) - 1;

		template <mint t_nBytesCache, typename t_CNewBytes>
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
				t_CNewBytes::fs_NewBytes(m_Bytes);
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

		struct CNewBytesRandom
		{
			static void fs_NewBytes(uint8 *o_pBytes)
			{
				auto Values = NMisc::fg_GetRandomUnsigned();
				o_pBytes[0] = Values & 0xff;
				o_pBytes[1] = (Values >> 8) & 0xff;
				o_pBytes[2] = (Values >> 16) & 0xff;
				o_pBytes[3] = (Values >> 24) & 0xff;
			}
		};

		struct CNewBytesSecure
		{
			static void fs_NewBytes(uint8 *o_pBytes)
			{
				NMisc::fg_SecureRandomThreadLocal().f_GetBytes(o_pBytes, 8);
			}
		};

		struct CNewBytesHighEntropy
		{
			static void fs_NewBytes(uint8 *o_pBytes)
			{
				NSys::fg_Security_GenerateHighEntropyData(o_pBytes, 8);
			}
		};

		using CUniformIntDistributionSecure = TCUniformIntDistribution<8, CNewBytesSecure>;
		using CUniformIntDistribution = TCUniformIntDistribution<4, CNewBytesRandom>;
		using CUniformIntDistributionHighEntropy = TCUniformIntDistribution<8, CNewBytesHighEntropy>;
	}

	NStr::CStr fg_RandomID(mint _Len)
	{
		NStr::CStr Return;
		{
			NStr::CStr::CAppender Appender(Return);

			// Use ChaCha20-based secure random (fast and cryptographically secure)
			CUniformIntDistributionSecure RandomDistribution(gc_nChars);
			for (mint i = 0; i < _Len; ++i)
				Appender += gc_UnmistakableChars[RandomDistribution()];
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
				Appender += gc_UnmistakableChars[RandomDistribution()];
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

			// Use ChaCha20-based secure random (fast and cryptographically secure)
			CUniformIntDistributionSecure RandomDistribution(nChars);
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

	NStr::CStr fg_FastRandomID(mint _Len)
	{
		NStr::CStr Return;
		{
			NStr::CStr::CAppender Appender(Return);

			// Use fast XorShift RNG (not cryptographically secure, but very fast)
			CUniformIntDistribution RandomDistribution(gc_nChars);
			for (mint i = 0; i < _Len; ++i)
				Appender += gc_UnmistakableChars[RandomDistribution()];
		}

		return Return;
	}

	NStr::CStrSecure fg_FastRandomID(ch8 const *_pCharacters, mint _Len)
	{
		mint nChars = NStr::fg_StrLen(_pCharacters);
		DMibFastCheck(nChars > 0);

		NStr::CStrSecure Return;
		{
			NStr::CStrSecure::CAppender Appender(Return);

			// Use fast XorShift RNG (not cryptographically secure, but very fast)
			CUniformIntDistribution RandomDistribution(nChars);
			for (mint i = 0; i < _Len; ++i)
				Appender += _pCharacters[RandomDistribution()];
		}

		return Return;
	}
}
