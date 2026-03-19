// Copyright © 2023 Favro Holding AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Cryptography/RandomID>

namespace NMib::NCryptography
{
	NStr::CStrSecure fg_RandomID(ch8 const *_pCharacters, umint _Len);
}

namespace
{
	using namespace NMib::NTest;
	using namespace NMib::NStr;
	using namespace NMib::NContainer;
	using namespace NMib::NCryptography;

	struct CRandomID_Tests : public CTest
	{
		template <auto tf_fGetID>
		void f_Test(CStr const &_Name, umint _nChars)
		{
			DMibTestCategory(_Name)
			{
				DMibTestCategory("Length")
				{
					DMibExpect(tf_fGetID(1).f_GetLen(), ==, 1);
					DMibExpect(tf_fGetID(2).f_GetLen(), ==, 2);
					DMibExpect(tf_fGetID(3).f_GetLen(), ==, 3);
					DMibExpect(tf_fGetID(4).f_GetLen(), ==, 4);
					DMibExpect(tf_fGetID(5).f_GetLen(), ==, 5);
					DMibExpect(tf_fGetID(6).f_GetLen(), ==, 6);
					DMibExpect(tf_fGetID(7).f_GetLen(), ==, 7);
					DMibExpect(tf_fGetID(8).f_GetLen(), ==, 8);
				};
				DMibTestCategory("Distribution")
				{
					umint nIDs = _nChars * 100;
					TCMap<CStrSecure, zmint> Distribution;
					for (umint i = 0; i < nIDs; ++i)
						++Distribution[tf_fGetID(1)];
					DMibExpect(Distribution.f_GetLen(), ==, _nChars);
				};
			};
		}

		void f_DoTests()
		{
			DMibTestSuite("General")
			{
				f_Test
					<
						[](umint _Len)
						{
							return fg_RandomID(_Len);
						}
					>("RandomID", 55)
				;
				f_Test
					<
						[](umint _Len)
						{
							return fg_HighEntropyRandomID(_Len);
						}
					>("HighEntropyRandomID", 55)
				;
				f_Test
					<
						[](umint _Len)
						{
							return fg_RandomID("1234", _Len);
						}
					>("RandomID 4", 4)
				;
				f_Test
					<
						[](umint _Len)
						{
							return fg_RandomID("12345", _Len);
						}
					>("RandomID 5", 5)
				;
				f_Test
					<
						[](umint _Len)
						{
							return fg_HighEntropyRandomID("1234", _Len);
						}
					>("HighEntropyRandomID 4", 4)
				;
				f_Test
					<
						[](umint _Len)
						{
							return fg_HighEntropyRandomID("12345", _Len);
						}
					>("HighEntropyRandomID 5", 5)
				;
				f_Test
					<
						[](umint _Len)
						{
							return fg_FastRandomID(_Len);
						}
					>("FastRandomID", 55)
				;
				f_Test
					<
						[](umint _Len)
						{
							return fg_FastRandomID("1234", _Len);
						}
					>("FastRandomID 4", 4)
				;
				f_Test
					<
						[](umint _Len)
						{
							return fg_FastRandomID("12345", _Len);
						}
					>("FastRandomID 5", 5)
				;
			};
		}
	};

	DMibTestRegister(CRandomID_Tests, Malterlib::Cryptography);
}

