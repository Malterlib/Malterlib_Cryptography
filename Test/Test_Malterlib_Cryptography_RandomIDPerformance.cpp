// Copyright © 2025 Favro Holding AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Test/Test>
#include <Mib/Test/Performance>
#include <Mib/Cryptography/RandomID>

namespace NMib::NCryptography
{
#if defined(DMibDebug) || defined(DMibSanitizerEnabled)
	static constexpr umint mc_nIterations = 10'000;
#else
	static constexpr umint mc_nIterations = 100'000;
#endif

	namespace
	{
		using namespace NMib::NTest;
		using namespace NMib::NStr;
		using namespace NMib::NTime;

		struct CRandomIDPerformance_Tests : public CTest
		{
			template <typename tf_FGenerator>
			inline_never void fp_MeasureGenerator(CTestPerformanceMeasure &_Measure, tf_FGenerator const &_fGenerator, umint _nIterations)
			{
				DMibTestScopeMeasure(_Measure, _nIterations);
				for (umint i = 0; i < _nIterations; ++i)
					_fGenerator();
			}

			void f_TestShortIDs()
			{
				DMibTestSuite("Short IDs (17 chars)")
				{
					CTestPerformance PerfTest(0.0); // No tolerance - just compare

					CTestPerformanceMeasure FastMeasure("FastRandomID");
					fp_MeasureGenerator
						(
							FastMeasure
							, [] inline_always_lambda
							{
								return fg_FastRandomID(17);
							}
							, mc_nIterations
						)
					;
					PerfTest.f_AddBaseline(FastMeasure);

					CTestPerformanceMeasure SecureMeasure("RandomID (ChaCha20)");
					fp_MeasureGenerator
						(
							SecureMeasure
							, [] inline_always_lambda
							{
								return fg_RandomID(17);
							}
							, mc_nIterations
						)
					;
					PerfTest.f_Add(SecureMeasure);

					CTestPerformanceMeasure HighEntropyMeasure("HighEntropyRandomID (OS CSPRNG)");
					fp_MeasureGenerator
						(
							HighEntropyMeasure
							, [] inline_always_lambda
							{
								return fg_HighEntropyRandomID(17);
							}
							, mc_nIterations
						)
					;
					PerfTest.f_Add(HighEntropyMeasure);

					DMibExpectTrue(PerfTest);
				};
			}

			void f_TestLongIDs()
			{
				DMibTestSuite("Long IDs (64 chars)")
				{
					CTestPerformance PerfTest(0.0);

					CTestPerformanceMeasure FastMeasure("FastRandomID");
					fp_MeasureGenerator
						(
							FastMeasure
							, [] inline_always_lambda
							{
								return fg_FastRandomID(64);
							}
							, mc_nIterations
						)
					;
					PerfTest.f_AddBaseline(FastMeasure);

					CTestPerformanceMeasure SecureMeasure("RandomID (ChaCha20)");
					fp_MeasureGenerator
						(
							SecureMeasure
							, [] inline_always_lambda
							{
								 return fg_RandomID(64);
							}
							, mc_nIterations
						)
					;
					PerfTest.f_Add(SecureMeasure);

					CTestPerformanceMeasure HighEntropyMeasure("HighEntropyRandomID (OS CSPRNG)");
					fp_MeasureGenerator
						(
							HighEntropyMeasure
							, [] inline_always_lambda
							{
								return fg_HighEntropyRandomID(64);
							}
							, mc_nIterations
						)
					;
					PerfTest.f_Add(HighEntropyMeasure);

					DMibExpectTrue(PerfTest);
				};
			}

			void f_TestCustomCharset()
			{
				DMibTestSuite("Custom Charset (hex, 32 chars)")
				{
					CTestPerformance PerfTest(0.0);

					CTestPerformanceMeasure FastMeasure("FastRandomID");
					fp_MeasureGenerator
						(
							FastMeasure
							, [] inline_always_lambda
							{
								return fg_FastRandomID("0123456789abcdef", 32);
							}
							, mc_nIterations
						)
					;
					PerfTest.f_AddBaseline(FastMeasure);

					CTestPerformanceMeasure SecureMeasure("RandomID (ChaCha20)");
					fp_MeasureGenerator
						(
							SecureMeasure
							, [] inline_always_lambda
							{
								return fg_RandomID("0123456789abcdef", 32);
							}
							, mc_nIterations
						)
					;
					PerfTest.f_Add(SecureMeasure);

					CTestPerformanceMeasure HighEntropyMeasure("HighEntropyRandomID (OS CSPRNG)");
					fp_MeasureGenerator
						(
							HighEntropyMeasure
							, [] inline_always_lambda
							{
								return fg_HighEntropyRandomID("0123456789abcdef", 32);
							}
							, mc_nIterations
						)
					;
					PerfTest.f_Add(HighEntropyMeasure);

					DMibExpectTrue(PerfTest);
				};
			}

			void f_DoTests()
			{
				DMibTestCategory(CTestCategory("Performance") << CTestGroup("Performance"))
				{
					f_TestShortIDs();
					f_TestLongIDs();
					f_TestCustomCharset();
				};
			}
		};

		DMibTestRegister(CRandomIDPerformance_Tests, Malterlib::Cryptography);
	}
}
