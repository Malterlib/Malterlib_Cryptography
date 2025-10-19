// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Test/Exception>
#include <Mib/Cryptography/Certificate>
#include "../Source/Malterlib_Cryptography_SignFiles.h"
#include <Mib/File/File>
#include <Mib/Encoding/EJson>

using namespace NMib;
using namespace NMib::NStr;
using namespace NMib::NContainer;
using namespace NMib::NCryptography;
using namespace NMib::NFile;

class CSignFiles_Tests : public NMib::NTest::CTest
{
public:
	static void fs_SetupTestPath(CStr const &_RootDirectory)
	{
		if (CFile::fs_FileExists(_RootDirectory))
			CFile::fs_DeleteDirectoryRecursive(_RootDirectory);

		CFile::fs_CreateDirectory(_RootDirectory);
		fg_TestAddCleanupPath(_RootDirectory);
	}

	void f_DoTests()
	{
		DMibTestSuite("Sign and Verify Single File") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_SingleFile";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate;
			CSecureByteVector PrivateKey;
			CCertificateOptions Options;
			Options.m_CommonName = "Test Code Signing";
			Options.m_KeySetting = CPublicKeySettings_EC_secp256r1{};
			Options.f_AddExtension_KeyUsage(EKeyUsage_DigitalSignature);
			Options.f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage_CodeSigning);

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Certificate, PrivateKey);

			CStr TestFilePath = RootPath / "TestSignFile.txt";
			CStr TestContent = "This is a test file for code signing.\nIt has multiple lines.\n";
			CFile::fs_WriteStringToFile(TestFilePath, TestContent);

			auto SignFunctor = fg_SignFiles(TestFilePath, fg_Move(PrivateKey), Certificate);
			NEncoding::CEJsonSorted SignatureJson = co_await SignFunctor();

			DMibExpectTrue(SignatureJson.f_GetMember("DigestAlgorithm") != nullptr);
			DMibExpectTrue(SignatureJson.f_GetMember("InputType") != nullptr);
			DMibExpectTrue(SignatureJson.f_GetMember("Manifest") != nullptr);
			DMibExpectTrue(SignatureJson.f_GetMember("Signature") != nullptr);
			DMibExpectTrue(SignatureJson.f_GetMember("Certificate") != nullptr);
			DMibExpectTrue(SignatureJson.f_GetMember("MessageLength") != nullptr);

			DMibExpect(SignatureJson["InputType"].f_String(), ==, "File");

			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate);

			CVerifyOptions VerifyOpts;
			VerifyOpts.m_Flags = EVerifyFlag::mc_None; // Don't require timestamp for this test

			auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs, VerifyOpts);
			auto Result = co_await VerifyFunctor().f_Wrap();
			DMibExpectTrue(Result);

			co_return {};
		};

		DMibTestSuite("Sign and Verify Directory") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_Directory";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate;
			CSecureByteVector PrivateKey;
			CCertificateOptions Options;
			Options.m_CommonName = "Test Code Signing";
			Options.m_KeySetting = CPublicKeySettings_EC_secp384r1{};
			Options.f_AddExtension_KeyUsage(EKeyUsage_DigitalSignature);
			Options.f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage_CodeSigning);

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Certificate, PrivateKey);

			CStr TestDirPath = RootPath / "TestSignDir";
			CFile::fs_CreateDirectory(TestDirPath);

			CFile::fs_WriteStringToFile(TestDirPath / "File1.txt", "Content of file 1");
			CFile::fs_WriteStringToFile(TestDirPath / "File2.txt", "Content of file 2");
			CFile::fs_CreateDirectory(TestDirPath / "SubDir");
			CFile::fs_WriteStringToFile(TestDirPath / "SubDir" / "File3.txt", "Content of file 3");

			auto SignFunctor = fg_SignFiles(TestDirPath, fg_Move(PrivateKey), Certificate, EDigestType_SHA384);
			NEncoding::CEJsonSorted SignatureJson = co_await SignFunctor();

			DMibExpect(SignatureJson["InputType"].f_String(), ==, "Directory");
			DMibExpect(SignatureJson["DigestAlgorithm"].f_String(), ==, "SHA384");

			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate);

			CVerifyOptions VerifyOpts;
			VerifyOpts.m_Flags = EVerifyFlag::mc_None; // Don't require timestamp for this test

			auto VerifyFunctor = fg_VerifyFiles(TestDirPath, SignatureJson, TrustedCAs, VerifyOpts);
			auto Result = co_await VerifyFunctor().f_Wrap();
			DMibExpectTrue(Result);

			co_return {};
		};

		DMibTestSuite("Verify Fails with Modified File") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_ModifiedFile";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate;
			CSecureByteVector PrivateKey;
			CCertificateOptions Options;
			Options.m_CommonName = "Test Code Signing";
			Options.m_KeySetting = CPublicKeySettings_EC_secp521r1{};
			Options.f_AddExtension_KeyUsage(EKeyUsage_DigitalSignature);

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Certificate, PrivateKey);

			CStr TestFilePath = RootPath / "TestTamperFile.txt";
			CFile::fs_WriteStringToFile(TestFilePath, "Original content");

			auto SignFunctor = fg_SignFiles(TestFilePath, fg_Move(PrivateKey), Certificate);
			NEncoding::CEJsonSorted SignatureJson = co_await SignFunctor();

			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate);

			CVerifyOptions VerifyOpts;
			VerifyOpts.m_Flags = EVerifyFlag::mc_None; // Don't require timestamp for this test

			{
				CFile::fs_WriteStringToFile(TestFilePath, "Modified content");
				auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs, VerifyOpts);
				auto Result = co_await VerifyFunctor().f_Wrap();
				DMibExpectException(Result.f_Get(), DMibErrorInstance("Signature verification failed"));
			}

			{
				CFile::fs_WriteStringToFile(TestFilePath, "Original content 2");
				auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs, VerifyOpts);
				auto Result = co_await VerifyFunctor().f_Wrap();
				DMibExpectException(Result.f_Get(), DMibErrorInstance("File length mismatch for file"));
			}

			co_return {};
		};

		DMibTestSuite("Verify Fails with different types") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_DifferentTypes";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate;
			CSecureByteVector PrivateKey;
			CCertificateOptions Options;
			Options.m_CommonName = "Test Code Signing";
			Options.m_KeySetting = CPublicKeySettings_EC_secp521r1{};
			Options.f_AddExtension_KeyUsage(EKeyUsage_DigitalSignature);

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Certificate, PrivateKey);

			CStr TestFilePath = RootPath / "TestTamperFile.txt";
			CFile::fs_WriteStringToFile(TestFilePath, "Original content");

			auto SignFunctor = fg_SignFiles(TestFilePath, fg_Move(PrivateKey), Certificate);
			NEncoding::CEJsonSorted SignatureJson = co_await SignFunctor();

			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate);

			CVerifyOptions VerifyOpts;
			VerifyOpts.m_Flags = EVerifyFlag::mc_None; // Don't require timestamp for this test

			{
				auto VerifyFunctor = fg_VerifyFiles(RootPath, SignatureJson, TrustedCAs, VerifyOpts);
				auto Result = co_await VerifyFunctor().f_Wrap();
				DMibExpectException(Result.f_Get(), DMibErrorInstance("InputType mismatch: expected File, got Directory"));
			}

			co_return {};
		};

		DMibTestSuite("Verify Fails with Modified Directory") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_ModifiedDirectory";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate;
			CSecureByteVector PrivateKey;
			CCertificateOptions Options;
			Options.m_CommonName = "Test Code Signing";
			Options.m_KeySetting = CPublicKeySettings_EC_secp384r1{};
			Options.f_AddExtension_KeyUsage(EKeyUsage_DigitalSignature);
			Options.f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage_CodeSigning);

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Certificate, PrivateKey);

			CStr TestDirPath = RootPath / "TestSignDir";
			CFile::fs_CreateDirectory(TestDirPath);

			CFile::fs_WriteStringToFile(TestDirPath / "File1.txt", "Content of file 1");
			CFile::fs_WriteStringToFile(TestDirPath / "File2.txt", "Content of file 2");
			CFile::fs_CreateDirectory(TestDirPath / "SubDir");
			CFile::fs_WriteStringToFile(TestDirPath / "SubDir" / "File3.txt", "Content of file 3");

			auto SignFunctor = fg_SignFiles(TestDirPath, fg_Move(PrivateKey), Certificate, EDigestType_SHA384);
			NEncoding::CEJsonSorted SignatureJson = co_await SignFunctor();

			DMibExpect(SignatureJson["InputType"].f_String(), ==, "Directory");
			DMibExpect(SignatureJson["DigestAlgorithm"].f_String(), ==, "SHA384");

			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate);

			CVerifyOptions VerifyOpts;
			VerifyOpts.m_Flags = EVerifyFlag::mc_None; // Don't require timestamp for this test

			{
				CFile::fs_WriteStringToFile(TestDirPath / "File1.txt", "Content of file 3");
				auto VerifyFunctor = fg_VerifyFiles(TestDirPath, SignatureJson, TrustedCAs, VerifyOpts);
				auto Result = co_await VerifyFunctor().f_Wrap();
				DMibExpectException(Result.f_Get(), DMibErrorInstance("Signature verification failed"));
			}

			{
				CFile::fs_WriteStringToFile(TestDirPath / "File1.txt", "Content of file 1 appended");
				auto VerifyFunctor = fg_VerifyFiles(TestDirPath, SignatureJson, TrustedCAs, VerifyOpts);
				auto Result = co_await VerifyFunctor().f_Wrap();
				DMibExpectException(Result.f_Get(), DMibErrorInstance("File length mismatch for File1.txt"));
			}

			co_return {};
		};

		DMibTestSuite("Verify Fails with Wrong CA") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_WrongCA";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate1;
			CSecureByteVector PrivateKey1;
			CCertificateOptions Options1;
			Options1.m_CommonName = "Code Signing Cert 1";
			Options1.m_KeySetting = CPublicKeySettings_EC_secp256r1{};

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options1, Certificate1, PrivateKey1);

			CByteVector Certificate2;
			CSecureByteVector PrivateKey2;
			CCertificateOptions Options2;
			Options2.m_CommonName = "Code Signing Cert 2";
			Options2.m_KeySetting = CPublicKeySettings_EC_secp256r1{};

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options2, Certificate2, PrivateKey2);

			CStr TestFilePath = RootPath / "test_wrong_ca.txt";
			CFile::fs_WriteStringToFile(TestFilePath, "Test content");

			auto SignFunctor = fg_SignFiles(TestFilePath, fg_Move(PrivateKey1), Certificate1);
			NEncoding::CEJsonSorted SignatureJson = co_await SignFunctor();

			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate2); // Wrong CA!

			CVerifyOptions VerifyOpts;
			VerifyOpts.m_Flags = EVerifyFlag::mc_None; // Don't require timestamp for this test

			auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs, VerifyOpts);
			auto Result = co_await VerifyFunctor().f_Wrap();
			NException::CExceptionPointer pDummy;
			DMibExpectException(Result.f_Get(), DMibErrorInstanceWrapped("Failed to verify certificate: Certificate chain verification failed: self signed certificate", pDummy));

			co_return {};
		};

		DMibTestSuite("Sign with CA-signed Certificate") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_CASigned";
			fs_SetupTestPath(RootPath);

			CByteVector CACertificate;
			CSecureByteVector CAPrivateKey;
			CCertificateOptions CAOptions;
			CAOptions.m_CommonName = "Test Root CA";
			CAOptions.m_KeySetting = CPublicKeySettings_RSA{2048};
			CAOptions.f_MakeCA();

			CCertificate::fs_GenerateSelfSignedCertAndKey(CAOptions, CACertificate, CAPrivateKey);

			CByteVector SigningCertRequest;
			CSecureByteVector SigningPrivateKey;
			CCertificateOptions SigningOptions;
			SigningOptions.m_CommonName = "Code Signing Certificate";
			SigningOptions.m_KeySetting = CPublicKeySettings_EC_secp256r1{};
			SigningOptions.f_AddExtension_KeyUsage(EKeyUsage_DigitalSignature);
			SigningOptions.f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage_CodeSigning);

			CCertificate::fs_GenerateClientCertificateRequest(SigningOptions, SigningCertRequest, SigningPrivateKey);

			CByteVector SigningCertificate;
			CCertificate::fs_SignClientCertificate(CACertificate, CAPrivateKey, SigningCertRequest, SigningCertificate);

			CStr TestFilePath = RootPath / "test_ca_signed.txt";
			CFile::fs_WriteStringToFile(TestFilePath, "Content signed with CA-issued certificate");

			auto SignFunctor = fg_SignFiles(TestFilePath, fg_Move(SigningPrivateKey), SigningCertificate);
			NEncoding::CEJsonSorted SignatureJson = co_await SignFunctor();

			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(CACertificate);

			CVerifyOptions VerifyOpts;
			VerifyOpts.m_Flags = EVerifyFlag::mc_None; // Don't require timestamp for this test

			auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs, VerifyOpts);
			auto Result = co_await VerifyFunctor().f_Wrap();
			DMibExpectTrue(Result);

			co_return {};
		};

		DMibTestSuite("Different Digest Algorithms") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_DigestAlgos";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate;
			CSecureByteVector PrivateKey;
			CCertificateOptions Options;
			Options.m_CommonName = "Test Digest Algorithms";
			Options.m_KeySetting = CPublicKeySettings_EC_secp256r1{};

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Certificate, PrivateKey);

			CStr TestFilePath = RootPath / "test_digest_algos.txt";
			CFile::fs_WriteStringToFile(TestFilePath, "Test content for digest algorithms");

			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate);

			CVerifyOptions VerifyOpts;
			VerifyOpts.m_Flags = EVerifyFlag::mc_None; // Don't require timestamp for this test

			{
				DMibTestPath("SHA256");
				auto SignFunctor = fg_SignFiles(TestFilePath, CSecureByteVector(PrivateKey), Certificate, EDigestType_SHA256);
				NEncoding::CEJsonSorted SignatureJson = co_await SignFunctor();
				DMibExpect(SignatureJson["DigestAlgorithm"].f_String(), ==, "SHA256");

				auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs, VerifyOpts);
				auto Result = co_await VerifyFunctor().f_Wrap();
				DMibExpectTrue(Result);
			}

			{
				DMibTestPath("SHA384");
				auto SignFunctor = fg_SignFiles(TestFilePath, CSecureByteVector(PrivateKey), Certificate, EDigestType_SHA384);
				NEncoding::CEJsonSorted SignatureJson = co_await SignFunctor();
				DMibExpect(SignatureJson["DigestAlgorithm"].f_String(), ==, "SHA384");

				auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs, VerifyOpts);
				auto Result = co_await VerifyFunctor().f_Wrap();
				DMibExpectTrue(Result);
			}

			{
				DMibTestPath("SHA512");
				auto SignFunctor = fg_SignFiles(TestFilePath, CSecureByteVector(PrivateKey), Certificate, EDigestType_SHA512);
				NEncoding::CEJsonSorted SignatureJson = co_await SignFunctor();
				DMibExpect(SignatureJson["DigestAlgorithm"].f_String(), ==, "SHA512");

				auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs, VerifyOpts);
				auto Result = co_await VerifyFunctor().f_Wrap();
				DMibExpectTrue(Result);
			}

			co_return {};
		};

		DMibTestSuite("Verify Fails with Extra Files") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_ExtraFiles";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate;
			CSecureByteVector PrivateKey;
			CCertificateOptions Options;
			Options.m_CommonName = "Test Code Signing";
			Options.m_KeySetting = CPublicKeySettings_EC_secp256r1{};

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Certificate, PrivateKey);

			CStr TestDirPath = RootPath / "TestSignDir";
			CFile::fs_CreateDirectory(TestDirPath);

			CFile::fs_WriteStringToFile(TestDirPath / "File1.txt", "Content of file 1");
			CFile::fs_WriteStringToFile(TestDirPath / "File2.txt", "Content of file 2");

			auto SignFunctor = fg_SignFiles(TestDirPath, fg_Move(PrivateKey), Certificate);
			NEncoding::CEJsonSorted SignatureJson = co_await SignFunctor();

			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate);

			CVerifyOptions VerifyOpts;
			VerifyOpts.m_Flags = EVerifyFlag::mc_None; // Don't require timestamp for this test

			// Add an extra file that wasn't in the original signature
			CFile::fs_WriteStringToFile(TestDirPath / "extra_file.txt", "This file was not signed");

			auto VerifyFunctor = fg_VerifyFiles(TestDirPath, SignatureJson, TrustedCAs, VerifyOpts);
			auto Result = co_await VerifyFunctor().f_Wrap();
			DMibExpectException(Result.f_Get(), DMibErrorInstance("Unexpected file found in directory: extra_file.txt"));

			co_return {};
		};

		DMibTestSuite("Sign with Timestamp using DigiCert TSA") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_TimestampDigiCert";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate;
			CSecureByteVector PrivateKey;
			CCertificateOptions Options;
			Options.m_CommonName = "Test Code Signing with Timestamp";
			Options.m_KeySetting = CPublicKeySettings_EC_secp256r1{};
			Options.f_AddExtension_KeyUsage(EKeyUsage_DigitalSignature);
			Options.f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage_CodeSigning);

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Certificate, PrivateKey);

			CStr TestFilePath = RootPath / "TestTimestampFile.txt";
			CStr TestContent = "This file will be signed with a RFC 3161 timestamp from DigiCert TSA.\n";
			CFile::fs_WriteStringToFile(TestFilePath, TestContent);

			CTimestampOptions TimestampOpts;
			// FreeTSA is a free public TSA that supports HTTPS
			TimestampOpts.m_TimestampURLs.f_InsertLast("http://timestamp.digicert.com");
			// Leave m_TimestampTrustedCACertificates empty to use system certificates

			auto SignFunctor = fg_SignFiles(TestFilePath, fg_Move(PrivateKey), Certificate, EDigestType_SHA256, TimestampOpts);

			auto SignResult = co_await SignFunctor().f_Wrap();
			DMibExpectTrue(SignResult);

			NEncoding::CEJsonSorted SignatureJson = *SignResult;

			// Verify that timestamp token is present
			DMibExpectTrue(SignatureJson.f_GetMember("TimestampToken") != nullptr);
			DMibExpectTrue(SignatureJson["TimestampToken"].f_IsBinary());
			DMibExpectTrue(SignatureJson["TimestampToken"].f_Binary().f_GetLen() > 0);

			DMibConOut2("Timestamp token size: {} bytes\n", SignatureJson["TimestampToken"].f_Binary().f_GetLen());

			// Verify the signature with timestamp
			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate);

			auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs);
			auto VerifyResult = co_await VerifyFunctor().f_Wrap();
			DMibExpectTrue(VerifyResult);

			co_return {};
		};

		DMibTestSuite("Sign with Timestamp using Multiple TSAs") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_TimestampMultiple";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate;
			CSecureByteVector PrivateKey;
			CCertificateOptions Options;
			Options.m_CommonName = "Test Code Signing with Timestamp";
			Options.m_KeySetting = CPublicKeySettings_EC_secp384r1{};
			Options.f_AddExtension_KeyUsage(EKeyUsage_DigitalSignature);
			Options.f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage_CodeSigning);

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Certificate, PrivateKey);

			CStr TestFilePath = RootPath / "TestTimestampFile.txt";
			CStr TestContent = "This file will be signed with a RFC 3161 timestamp.\n";
			CFile::fs_WriteStringToFile(TestFilePath, TestContent);

			CTimestampOptions TimestampOpts;
			// Note: HTTP is acceptable for RFC 3161 as the timestamp response is cryptographically signed
			TimestampOpts.m_TimestampURLs.f_InsertLast("http://timestamp.sectigo.com");
			TimestampOpts.m_TimestampURLs.f_InsertLast("http://timestamp.digicert.com"); // Fallback

			auto SignFunctor = fg_SignFiles(TestFilePath, fg_Move(PrivateKey), Certificate, EDigestType_SHA384, TimestampOpts);

			auto SignResult = co_await SignFunctor().f_Wrap();
			DMibExpectTrue(SignResult);

			NEncoding::CEJsonSorted SignatureJson = *SignResult;

			// Verify that timestamp token is present
			DMibExpectTrue(SignatureJson.f_GetMember("TimestampToken") != nullptr);
			DMibExpectTrue(SignatureJson["TimestampToken"].f_IsBinary());
			DMibExpectTrue(SignatureJson["TimestampToken"].f_Binary().f_GetLen() > 0);

			DMibConOut2("Timestamp token size: {} bytes\n", SignatureJson["TimestampToken"].f_Binary().f_GetLen());
			DMibConOut2("Digest algorithm: {}\n", SignatureJson["DigestAlgorithm"].f_String());

			// Verify the signature with timestamp
			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate);

			auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs);
			auto VerifyResult = co_await VerifyFunctor().f_Wrap();
			DMibExpectTrue(VerifyResult);

			co_return {};
		};

		DMibTestSuite("Sign with Multiple Timestamp URLs (Fallback)") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_TimestampFallback";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate;
			CSecureByteVector PrivateKey;
			CCertificateOptions Options;
			Options.m_CommonName = "Test Timestamp Fallback";
			Options.m_KeySetting = CPublicKeySettings_EC_secp256r1{};
			Options.f_AddExtension_KeyUsage(EKeyUsage_DigitalSignature);

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Certificate, PrivateKey);

			CStr TestFilePath = RootPath / "TestFallback.txt";
			CFile::fs_WriteStringToFile(TestFilePath, "Testing timestamp fallback");

			CTimestampOptions TimestampOpts;
			// First URL is intentionally invalid, should fall back to second
			TimestampOpts.m_TimestampURLs.f_InsertLast("http://invalid-timestamp-server.example.com");
			TimestampOpts.m_TimestampURLs.f_InsertLast("http://timestamp.digicert.com");

			auto SignFunctor = fg_SignFiles(TestFilePath, fg_Move(PrivateKey), Certificate, EDigestType_SHA256, TimestampOpts);

			auto SignResult = co_await SignFunctor().f_Wrap();
			// Should succeed with fallback to second URL
			DMibExpectTrue(SignResult);

			NEncoding::CEJsonSorted SignatureJson = *SignResult;

			// Verify that timestamp token is present (from fallback server)
			DMibExpectTrue(SignatureJson.f_GetMember("TimestampToken") != nullptr);
			DMibExpectTrue(SignatureJson["TimestampToken"].f_IsBinary());
			DMibExpectTrue(SignatureJson["TimestampToken"].f_Binary().f_GetLen() > 0);

			// Verify the signature
			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate);

			auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs);
			auto VerifyResult = co_await VerifyFunctor().f_Wrap();
			DMibExpectTrue(VerifyResult);

			co_return {};
		};

		DMibTestSuite("Sign Directory with Timestamp") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_DirectoryTimestamp";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate;
			CSecureByteVector PrivateKey;
			CCertificateOptions Options;
			Options.m_CommonName = "Test Directory with Timestamp";
			Options.m_KeySetting = CPublicKeySettings_EC_secp256r1{};
			Options.f_AddExtension_KeyUsage(EKeyUsage_DigitalSignature);

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Certificate, PrivateKey);

			CStr TestDirPath = RootPath / "TestSignDir";
			CFile::fs_CreateDirectory(TestDirPath);

			CFile::fs_WriteStringToFile(TestDirPath / "File1.txt", "Content of file 1");
			CFile::fs_WriteStringToFile(TestDirPath / "File2.txt", "Content of file 2");
			CFile::fs_CreateDirectory(TestDirPath / "SubDir");
			CFile::fs_WriteStringToFile(TestDirPath / "SubDir" / "File3.txt", "Content of file 3");

			CTimestampOptions TimestampOpts;
			TimestampOpts.m_TimestampURLs.f_InsertLast("http://timestamp.digicert.com");

			auto SignFunctor = fg_SignFiles(TestDirPath, fg_Move(PrivateKey), Certificate, EDigestType_SHA512, TimestampOpts);

			auto SignResult = co_await SignFunctor().f_Wrap();
			DMibExpectTrue(SignResult);

			NEncoding::CEJsonSorted SignatureJson = *SignResult;

			DMibExpect(SignatureJson["InputType"].f_String(), ==, "Directory");
			DMibExpect(SignatureJson["DigestAlgorithm"].f_String(), ==, "SHA512");
			DMibExpectTrue(SignatureJson.f_GetMember("TimestampToken") != nullptr);
			DMibExpectTrue(SignatureJson["TimestampToken"].f_Binary().f_GetLen() > 0);

			// Verify the signature with timestamp
			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate);

			auto VerifyFunctor = fg_VerifyFiles(TestDirPath, SignatureJson, TrustedCAs);
			auto VerifyResult = co_await VerifyFunctor().f_Wrap();
			DMibExpectTrue(VerifyResult);

			co_return {};
		};

		DMibTestSuite("Timestamp Verification Rejects Invalid CA") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_TimestampInvalidCA";
			fs_SetupTestPath(RootPath);

			// Generate signing certificate
			CByteVector SigningCertificate;
			CSecureByteVector SigningPrivateKey;
			CCertificateOptions SigningOptions;
			SigningOptions.m_CommonName = "Test Code Signing";
			SigningOptions.m_KeySetting = CPublicKeySettings_EC_secp256r1{};
			SigningOptions.f_AddExtension_KeyUsage(EKeyUsage_DigitalSignature);
			SigningOptions.f_AddExtension_ExtendedKeyUsage(EExtendedKeyUsage_CodeSigning);

			CCertificate::fs_GenerateSelfSignedCertAndKey(SigningOptions, SigningCertificate, SigningPrivateKey);

			// Generate an unrelated CA certificate (not used for timestamp)
			CByteVector UnrelatedCA;
			CSecureByteVector UnrelatedPrivateKey;
			CCertificateOptions UnrelatedOptions;
			UnrelatedOptions.m_CommonName = "Unrelated CA";
			UnrelatedOptions.m_KeySetting = CPublicKeySettings_EC_secp384r1{};
			UnrelatedOptions.f_AddExtension_BasicConstraints(true, 1); // This is a CA

			CCertificate::fs_GenerateSelfSignedCertAndKey(UnrelatedOptions, UnrelatedCA, UnrelatedPrivateKey);

			CStr TestFilePath = RootPath / "TestInvalidCA.txt";
			CFile::fs_WriteStringToFile(TestFilePath, "This file is signed with a timestamp");

			// Sign with timestamp
			CTimestampOptions TimestampOpts;
			TimestampOpts.m_TimestampURLs.f_InsertLast("http://timestamp.digicert.com");

			auto SignFunctor = fg_SignFiles(TestFilePath, fg_Move(SigningPrivateKey), SigningCertificate, EDigestType_SHA256, TimestampOpts);

			auto SignResult = co_await SignFunctor().f_Wrap();
			DMibExpectTrue(SignResult);

			NEncoding::CEJsonSorted SignatureJson = *SignResult;

			// Verify that timestamp token is present
			DMibExpectTrue(SignatureJson.f_GetMember("TimestampToken") != nullptr);

			// Try to verify with signing CA (valid for signature)
			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(SigningCertificate);

			// But use an unrelated CA for timestamp validation (should fail)
			CVerifyOptions VerifyOpts;
			VerifyOpts.m_TimestampTrustedCACertificates.f_InsertLast(UnrelatedCA);

			auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs, VerifyOpts);
			auto VerifyResult = co_await VerifyFunctor().f_Wrap();

			// Should FAIL because the unrelated CA cannot validate the timestamp
			DMibExpectFalse(VerifyResult);
			NException::CExceptionPointer pDummy;
			DMibExpectException
				(
					VerifyResult.f_Get()
					, DMibErrorInstanceWrapped("Exception while verifying files: Timestamp certificate chain verification failed: unable to get local issuer certificate", pDummy)
				)
			;

			co_return {};
		};

		DMibTestSuite("Verify Signature Without Timestamp With mc_None Flag") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_NoTimestamp";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate;
			CSecureByteVector PrivateKey;
			CCertificateOptions Options;
			Options.m_CommonName = "Test No Timestamp";
			Options.m_KeySetting = CPublicKeySettings_EC_secp256r1{};

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Certificate, PrivateKey);

			CStr TestFilePath = RootPath / "TestNoTimestamp.txt";
			CFile::fs_WriteStringToFile(TestFilePath, "No timestamp on this signature");

			// Sign without timestamp options (empty)
			auto SignFunctor = fg_SignFiles(TestFilePath, fg_Move(PrivateKey), Certificate);
			NEncoding::CEJsonSorted SignatureJson = co_await SignFunctor();

			// Verify that NO timestamp token is present
			DMibExpectTrue(SignatureJson.f_GetMember("TimestampToken") == nullptr);

			// Verify the signature still works without timestamp when mc_None is used
			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate);

			CVerifyOptions VerifyOpts;
			VerifyOpts.m_Flags = EVerifyFlag::mc_None; // Don't require timestamp

			auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs, VerifyOpts);
			auto VerifyResult = co_await VerifyFunctor().f_Wrap();
			DMibExpectTrue(VerifyResult);

			co_return {};
		};

		DMibTestSuite("Verify Fails Without Timestamp When Required (Default)") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_RequireTimestamp";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate;
			CSecureByteVector PrivateKey;
			CCertificateOptions Options;
			Options.m_CommonName = "Test Require Timestamp";
			Options.m_KeySetting = CPublicKeySettings_EC_secp256r1{};

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Certificate, PrivateKey);

			CStr TestFilePath = RootPath / "TestRequireTimestamp.txt";
			CFile::fs_WriteStringToFile(TestFilePath, "This signature requires a timestamp");

			// Sign without timestamp options (empty)
			auto SignFunctor = fg_SignFiles(TestFilePath, fg_Move(PrivateKey), Certificate);
			NEncoding::CEJsonSorted SignatureJson = co_await SignFunctor();

			// Verify that NO timestamp token is present
			DMibExpectTrue(SignatureJson.f_GetMember("TimestampToken") == nullptr);

			// Verify with default options (timestamp required)
			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate);

			// Use default CVerifyOptions which requires timestamp (mc_Default = mc_RequireTimestamp)
			auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs);
			auto VerifyResult = co_await VerifyFunctor().f_Wrap();

			// Should FAIL because timestamp is required but not present
			DMibExpectFalse(VerifyResult);
			DMibExpectException(VerifyResult.f_Get(), DMibErrorInstance("Timestamp required but not present in signature"));

			co_return {};
		};

		DMibTestSuite("Verify Passes With Timestamp When Required (Default)") -> NConcurrency::TCFuture<void>
		{
			CStr RootPath = CFile::fs_GetProgramDirectory() / "SignFiles_RequireTimestampPass";
			fs_SetupTestPath(RootPath);

			CByteVector Certificate;
			CSecureByteVector PrivateKey;
			CCertificateOptions Options;
			Options.m_CommonName = "Test Require Timestamp Pass";
			Options.m_KeySetting = CPublicKeySettings_EC_secp256r1{};

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Certificate, PrivateKey);

			CStr TestFilePath = RootPath / "TestRequireTimestampPass.txt";
			CFile::fs_WriteStringToFile(TestFilePath, "This signature has a timestamp");

			// Sign WITH timestamp options
			CTimestampOptions TimestampOpts;
			TimestampOpts.m_TimestampURLs.f_InsertLast("http://timestamp.digicert.com");

			auto SignFunctor = fg_SignFiles(TestFilePath, fg_Move(PrivateKey), Certificate, EDigestType_SHA256, TimestampOpts);
			auto SignResult = co_await SignFunctor().f_Wrap();
			DMibExpectTrue(SignResult);

			NEncoding::CEJsonSorted SignatureJson = *SignResult;

			// Verify that timestamp token IS present
			DMibExpectTrue(SignatureJson.f_GetMember("TimestampToken") != nullptr);

			// Verify with default options (timestamp required) - should pass
			TCVector<CByteVector> TrustedCAs;
			TrustedCAs.f_InsertLast(Certificate);

			// Use default CVerifyOptions which requires timestamp
			auto VerifyFunctor = fg_VerifyFiles(TestFilePath, SignatureJson, TrustedCAs);
			auto VerifyResult = co_await VerifyFunctor().f_Wrap();
			DMibExpectTrue(VerifyResult);

			co_return {};
		};
	}
};

DMibTestRegister(CSignFiles_Tests, Malterlib::Crytpography);
