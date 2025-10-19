// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Cryptography_SignFiles.h"

#include <cstring>

#include <Mib/Concurrency/AsyncDestroy>
#include <Mib/Cryptography/PublicCrypto>
#include <Mib/Cryptography/BoringSSL>
#include <Mib/Encoding/Base64>
#include <Mib/File/DirectoryManifest>
#include <Mib/File/File>
#include <Mib/File/Generators>
#include <Mib/Web/Curl>

#include "Malterlib_Cryptography_Hash_MD5.h"
#include "Malterlib_Cryptography_Hash_SHA.h"
#include "Malterlib_Cryptography_Certificate.h"
#include "Malterlib_Cryptography_Timestamp.h"

namespace NMib::NCryptography
{
	namespace
	{
		using namespace NBoringSSL;
		using namespace NStr;

		// Check if a certificate has a specific Extended Key Usage
		[[maybe_unused]] bool fg_CertificateHasEKU(X509 *_pCert, int _nidExtKeyUsage)
		{
			if (!_pCert)
				return false;

			// Get the extended key usage extension
			EXTENDED_KEY_USAGE *pExtKeyUsage = (EXTENDED_KEY_USAGE*)X509_get_ext_d2i(_pCert, NID_ext_key_usage, nullptr, nullptr);
			if (!pExtKeyUsage)
				return false;

			auto CleanupExtKeyUsage = g_OnScopeExit / [&]
				{
					EXTENDED_KEY_USAGE_free(pExtKeyUsage);
				}
			;

			// Check if the specified EKU is present
			for (int i = 0; i < sk_ASN1_OBJECT_num(pExtKeyUsage); ++i)
			{
				ASN1_OBJECT *pObj = sk_ASN1_OBJECT_value(pExtKeyUsage, i);
				if (OBJ_obj2nid(pObj) == _nidExtKeyUsage)
					return true;
			}

			return false;
		}

		// Get NID for digest algorithm
		int fg_DigestTypeToNID(EDigestType _DigestType)
		{
			switch (_DigestType)
			{
			case EDigestType_SHA256: return NID_sha256;
			case EDigestType_SHA384: return NID_sha384;
			case EDigestType_SHA512: return NID_sha512;
			default:
				DMibErrorCryptography("Unsupported digest type for timestamp");
			}
		}

		// Generate RFC 3161 timestamp request for a given message digest
		// Manually construct ASN.1 structure since BoringSSL doesn't have TS_* APIs
		NContainer::CByteVector fg_GenerateTimestampRequest(NContainer::CByteVector const &_MessageDigest, EDigestType _DigestType)
		{
			// RFC 3161 TimeStampReq structure:
			// TimeStampReq ::= SEQUENCE {
			//   version INTEGER { v1(1) },
			//   messageImprint MessageImprint,
			//   reqPolicy TSAPolicyId OPTIONAL,
			//   nonce INTEGER OPTIONAL,
			//   certReq BOOLEAN DEFAULT FALSE,
			//   extensions [0] IMPLICIT Extensions OPTIONAL
			// }
			// MessageImprint ::= SEQUENCE {
			//   hashAlgorithm AlgorithmIdentifier,
			//   hashedMessage OCTET STRING
			// }

			CBB cbb, tsReq, messageImprint, hashAlgorithm;

			if (!CBB_init(&cbb, 256))
				DMibErrorCryptography(fg_GetExceptionStr("CBB_init failed"));

			auto CleanupCBB = g_OnScopeExit / [&]
				{
					CBB_cleanup(&cbb);
				}
			;

			// Start TimeStampReq SEQUENCE
			if (!CBB_add_asn1(&cbb, &tsReq, CBS_ASN1_SEQUENCE))
				DMibErrorCryptography(fg_GetExceptionStr("CBB_add_asn1 failed for tsReq"));

			// Add version (v1 = 1)
			if (!CBB_add_asn1_uint64(&tsReq, 1))
				DMibErrorCryptography(fg_GetExceptionStr("CBB_add_asn1_uint64 failed for version"));

			// Start MessageImprint SEQUENCE
			if (!CBB_add_asn1(&tsReq, &messageImprint, CBS_ASN1_SEQUENCE))
				DMibErrorCryptography(fg_GetExceptionStr("CBB_add_asn1 failed for messageImprint"));

			// Add hashAlgorithm
			if (!CBB_add_asn1(&messageImprint, &hashAlgorithm, CBS_ASN1_SEQUENCE))
				DMibErrorCryptography(fg_GetExceptionStr("CBB_add_asn1 failed for hashAlgorithm"));

			// Add algorithm OID
			int nNID = fg_DigestTypeToNID(_DigestType);
			ASN1_OBJECT *pObj = OBJ_nid2obj(nNID);
			if (!pObj)
				DMibErrorCryptography(fg_GetExceptionStr("OBJ_nid2obj failed"));

			CBB objCBB;
			if (!CBB_add_asn1(&hashAlgorithm, &objCBB, CBS_ASN1_OBJECT))
				DMibErrorCryptography(fg_GetExceptionStr("CBB_add_asn1 failed for OID"));

			if (!CBB_add_bytes(&objCBB, OBJ_get0_data(pObj), OBJ_length(pObj)))
				DMibErrorCryptography(fg_GetExceptionStr("CBB_add_bytes failed for algorithm OID"));

			// Add NULL parameters for hash algorithm
			CBB nullCBB;
			if (!CBB_add_asn1(&hashAlgorithm, &nullCBB, CBS_ASN1_NULL))
				DMibErrorCryptography(fg_GetExceptionStr("CBB_add_asn1 failed for NULL"));
			// NULL has no content, so we don't write anything to nullCBB

			if (!CBB_flush(&messageImprint))
				DMibErrorCryptography(fg_GetExceptionStr("CBB_flush failed for hashAlgorithm"));

			// Add hashedMessage (OCTET STRING)
			if (!CBB_add_asn1_octet_string(&messageImprint, _MessageDigest.f_GetArray(), _MessageDigest.f_GetLen()))
				DMibErrorCryptography(fg_GetExceptionStr("CBB_add_asn1_octet_string failed"));

			if (!CBB_flush(&tsReq))
				DMibErrorCryptography(fg_GetExceptionStr("CBB_flush failed for messageImprint"));

			// Add certReq = TRUE
			if (!CBB_add_asn1_bool(&tsReq, 1))
				DMibErrorCryptography(fg_GetExceptionStr("CBB_add_asn1_bool failed for certReq"));

			if (!CBB_flush(&cbb))
				DMibErrorCryptography(fg_GetExceptionStr("CBB_flush failed for tsReq"));

			// Extract the result
			uint8 *pData = nullptr;
			size_t nLen = 0;
			if (!CBB_finish(&cbb, &pData, &nLen))
				DMibErrorCryptography(fg_GetExceptionStr("CBB_finish failed"));

			NContainer::CByteVector Result(pData, nLen);
			OPENSSL_free(pData);

			return Result;
		}

		// Parse and validate basic RFC 3161 timestamp response structure
		// Note: Full validation of PKCS7 signatures requires external tools due to BoringSSL's limited PKCS7 API
		NContainer::CByteVector fg_ParseTimestampResponse(NContainer::CByteVector const &_ResponseData)
		{
			// Parse TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL }
			CBS cbs, tsResp, statusInfo;
			CBS_init(&cbs, _ResponseData.f_GetArray(), _ResponseData.f_GetLen());

			if (!CBS_get_asn1(&cbs, &tsResp, CBS_ASN1_SEQUENCE))
				DMibErrorCryptography("Invalid timestamp response - not a SEQUENCE");

			// Parse PKIStatusInfo ::= SEQUENCE { status PKIStatus, ... }
			if (!CBS_get_asn1(&tsResp, &statusInfo, CBS_ASN1_SEQUENCE))
				DMibErrorCryptography("Invalid timestamp response - no status info");

			// Check status (0 = granted, 1 = grantedWithMods)
			// CBS_get_asn1_uint64 expects to parse the INTEGER tag itself
			uint64_t nStatus = 0;
			if (!CBS_get_asn1_uint64(&statusInfo, &nStatus))
			{
				CStr ErrorMsg = "Invalid timestamp response - could not get status value";
				DMibErrorCryptography(ErrorMsg);
			}

			if (nStatus != 0 && nStatus != 1)
			{
				CStr ErrorMsg = "Timestamp request failed with status {}"_f << nStatus;
				DMibErrorCryptography(ErrorMsg);
			}


			// Extract timeStampToken (PKCS7 signed data)
			CBS tokenCBS;
			if (!CBS_get_asn1_element(&tsResp, &tokenCBS, CBS_ASN1_SEQUENCE))
				DMibErrorCryptography("Timestamp response has no token");

			// Basic validation - parse as PKCS7 to ensure it's valid
			unsigned char const *pTokenData = CBS_data(&tokenCBS);
			PKCS7 *pToken = d2i_PKCS7(nullptr, &pTokenData, CBS_len(&tokenCBS));
			if (!pToken)
				DMibErrorCryptography(fg_GetExceptionStr("d2i_PKCS7 failed - invalid timestamp token"));

			PKCS7_free(pToken);

			// Return the complete timestamp token for embedding in signature
			return NContainer::CByteVector(CBS_data(&tokenCBS), CBS_len(&tokenCBS));
		}

		// Request timestamp from TSA server via HTTP POST
		NConcurrency::TCFuture<NContainer::CByteVector> fg_RequestTimestamp
			(
				NConcurrency::TCActor<NWeb::CCurlActor> _CurlActor
				, NStr::CStr _TimestampURL
				, NContainer::CByteVector _MessageDigest
				, EDigestType _DigestType
			)
		{
			auto CaptureScope = co_await (NConcurrency::g_CaptureExceptions % "Exception requesting timestamp");

			// Generate RFC 3161 timestamp request
			NContainer::CByteVector RequestData = fg_GenerateTimestampRequest(_MessageDigest, _DigestType);

			// Make HTTP POST request to TSA
			NWeb::CCurlActor::CRequest Request;
			Request.m_URL = fg_Move(_TimestampURL);
			Request.m_Method = NWeb::CCurlActor::EMethod_POST;
			Request.m_Headers["Content-Type"] = "application/timestamp-query";
			Request.m_Data = fg_Move(RequestData);

			auto Result = co_await _CurlActor(&NWeb::CCurlActor::f_ExecuteRequest, fg_Move(Request));

			if (Result.m_StatusCode != 200)
				co_return DMibErrorInstance("Timestamp server returned status {}: {}"_f << Result.m_StatusCode << Result.m_StatusMessage);

			// Parse and validate the response
			NContainer::CByteVector ResponseBytes = NContainer::CByteVector::fs_FromString(Result.m_Body);

			co_return fg_ParseTimestampResponse(ResponseBytes);
		}

		NStr::CStr fg_DigestTypeToStr(EDigestType _DigestType)
		{
			switch (_DigestType)
			{
			case EDigestType_SHA512: return "SHA512";
			case EDigestType_SHA384: return "SHA384";
			case EDigestType_SHA256: return "SHA256";
			default: break;
			}

			return "Unknown";
		}

		struct CSignParams
		{
			NStr::CStr m_RootPath;
			NFile::CDirectoryManifest m_Manifest;
			NContainer::CSecureByteVector m_PrivateKey;
			NContainer::CByteVector m_Certificate;
			EDigestType m_DigestType;
			NStorage::TCSharedPointer<NAtomic::TCAtomic<bool>> m_pAborted;
			bool m_bInputIsDirectory = false;
			NContainer::TCVector<NStr::CStr> m_TimestampURLs;
			NContainer::TCVector<NContainer::CByteVector> m_TimestampTrustedCAs;
		};

		NConcurrency::TCFuture<NEncoding::CEJsonSorted> fg_SignDetachedAsync(CSignParams _Params)
		{
			co_await NConcurrency::fg_ContinueRunningOnActor(NConcurrency::fg_ConcurrentActorHighCPU());

			auto CaptureScope = co_await (NConcurrency::g_CaptureExceptions % "Exception while signing files");

			using namespace NBoringSSL;

			auto pKey = fg_LoadPrivateKey(_Params.m_PrivateKey);
			auto CleanupKey = g_OnScopeExit / [&]
				{
					if (pKey)
						EVP_PKEY_free(pKey);
				}
			;

			auto pDigest = fg_GetDigest(_Params.m_DigestType, pKey);

			ERR_clear_error();
			auto pCtx = EVP_MD_CTX_create();
			if (!pCtx)
				co_return DMibErrorInstanceCryptography(fg_GetExceptionStr("EVP_MD_CTX_create failed"));

			auto CleanupCtx = g_OnScopeExit / [&]
				{
					EVP_MD_CTX_destroy(pCtx);
				}
			;

			ERR_clear_error();
			if (EVP_DigestSignInit(pCtx, nullptr, pDigest, nullptr, pKey) != 1)
				co_return DMibErrorInstanceCryptography(fg_GetExceptionStr("EVP_DigestSignInit failed"));

			NEncoding::CEJsonSorted Result;
			Result["DigestAlgorithm"] = fg_DigestTypeToStr(_Params.m_DigestType);
			Result["InputType"] = _Params.m_bInputIsDirectory ? "Directory" : "File";
			Result["Certificate"] = _Params.m_Certificate;

			uint64 MessageLength = 0;

			auto fAddToDigest = [&](void const *_pData, mint _Len)
				{
					if (!_Len)
						return;

					if (_Len > (TCLimitsInt<int64>::mc_Max - MessageLength))
						DMibErrorCryptography("Signed data exceeds supported size");

					MessageLength += _Len;

					ERR_clear_error();
					if (EVP_DigestSignUpdate(pCtx, _pData, _Len) != 1)
						DMibErrorCryptography(fg_GetExceptionStr("EVP_DigestSignUpdate failed"));
				}
			;

			auto fAddUInt64 = [&](uint64 _Value)
				{
					auto ValueLE = NMib::fg_ByteSwapLE(_Value);
					fAddToDigest(&ValueLE, sizeof(ValueLE));
				}
			;

			auto fAddString = [&](NStr::CStr const &_String)
				{
					fAddUInt64(uint64(_String.f_GetLen()));
					fAddToDigest(_String.f_GetStr(), _String.f_GetLen());
				}
			;

			for (auto &ManifestEntry : _Params.m_Manifest.m_Files)
			{
				if (_Params.m_pAborted->f_Load(NAtomic::EMemoryOrder_Relaxed))
					co_return DMibErrorInstance("Aborted");

				// Clear out sensitive info
				ManifestEntry.m_Owner.f_Clear();
				ManifestEntry.m_Group.f_Clear();

				if (ManifestEntry.m_Length > TCLimitsInt<int64>::mc_Max)
					co_return DMibErrorInstance("File too large to sign");

				if (ManifestEntry.f_IsFile())
				{
					fAddUInt64(ManifestEntry.m_Length);

					CHash_SHA256 FileHash;
					uint64 FileLength = 0;
					auto FileGenerator = NFile::fg_ReadFileGenerator(NFile::CReadFileGeneratorParams{.m_Path = _Params.m_RootPath / ManifestEntry.m_OriginalPath});

					for (auto iChunk = co_await fg_Move(FileGenerator).f_GetPipelinedIterator(); iChunk; co_await ++iChunk)
					{
						if (_Params.m_pAborted->f_Load(NAtomic::EMemoryOrder_Relaxed))
							co_return DMibErrorInstance("Aborted");

						auto const &Chunk = *iChunk;
						FileHash.f_AddData(Chunk.f_GetArray(), Chunk.f_GetLen());
						FileLength += Chunk.f_GetLen();

						fAddToDigest(Chunk.f_GetArray(), Chunk.f_GetLen());
					}

					if (ManifestEntry.m_Length != FileLength)
						co_return DMibErrorInstance("File contents changed during signing");

					ManifestEntry.m_Digest = FileHash.f_GetDigest();
					ManifestEntry.m_Length = FileLength;
				}
			}

			auto &ManifestJson = Result["Manifest"] = _Params.m_Manifest.f_ToJson();

			fAddString(ManifestJson.f_ToString(nullptr));

			Result["MessageLength"] = int64(MessageLength);

			mint SignatureLength = 0;

			ERR_clear_error();
			if (EVP_DigestSignFinal(pCtx, nullptr, &SignatureLength) != 1)
				co_return DMibErrorInstanceCryptography(fg_GetExceptionStr("EVP_DigestSignFinal failed"));

			NContainer::CSecureByteVector Signature;

			ERR_clear_error();
			if (EVP_DigestSignFinal(pCtx, Signature.f_GetArray(SignatureLength), &SignatureLength) != 1)
				co_return DMibErrorInstanceCryptography(fg_GetExceptionStr("EVP_DigestSignFinal failed"));

			Signature.f_SetLen(SignatureLength);
			Result["Signature"] = Signature.f_ToInsecure();

			// Request timestamp if URLs are provided
			if (!_Params.m_TimestampURLs.f_IsEmpty())
			{
				// Compute digest of the signature for timestamping
				NContainer::CByteVector SignatureDigest;
				switch (_Params.m_DigestType)
				{
				case EDigestType_SHA256:
					{
						CHash_SHA256 Hash;
						Hash.f_AddData(Signature.f_GetArray(), Signature.f_GetLen());
						auto Digest = Hash.f_GetDigest();
						SignatureDigest = NContainer::CByteVector((unsigned char const *)&Digest, sizeof(Digest));
					}
					break;
				case EDigestType_SHA384:
					{
						CHash_SHA384 Hash;
						Hash.f_AddData(Signature.f_GetArray(), Signature.f_GetLen());
						auto Digest = Hash.f_GetDigest();
						SignatureDigest = NContainer::CByteVector((unsigned char const *)&Digest, sizeof(Digest));
					}
					break;
				case EDigestType_SHA512:
					{
						CHash_SHA512 Hash;
						Hash.f_AddData(Signature.f_GetArray(), Signature.f_GetLen());
						auto Digest = Hash.f_GetDigest();
						SignatureDigest = NContainer::CByteVector((unsigned char const *)&Digest, sizeof(Digest));
					}
					break;
				default:
					co_return DMibErrorInstance("Unsupported digest type for timestamp");
				}

				// Try each timestamp URL until one succeeds
				NContainer::CByteVector TimestampToken;
				bool bTimestampSuccess = false;
				CStr LastError;

				// Create Curl actor for HTTP requests
				NConcurrency::TCActor<NWeb::CCurlActor> CurlActor{fg_Construct(), "Timestamp curl actor"};

				auto CurlActorDestroy = co_await NConcurrency::fg_AsyncDestroy(CurlActor);

				for (auto const &URL : _Params.m_TimestampURLs)
				{
					if (_Params.m_pAborted->f_Load(NAtomic::EMemoryOrder_Relaxed))
						co_return DMibErrorInstance("Aborted");

					auto TimestampResult = co_await fg_RequestTimestamp
						(
							CurlActor
							, URL
							, SignatureDigest
							, _Params.m_DigestType
						)
						.f_Wrap()
					;

					if (TimestampResult)
					{
						TimestampToken = fg_Move(*TimestampResult);
						bTimestampSuccess = true;
						break;
					}
					else
						LastError = "Failed to get timestamp from {}: {}"_f << URL << TimestampResult.f_GetExceptionStr();
				}

				if (!bTimestampSuccess)
					co_return DMibErrorInstance("Failed to get timestamp: {}"_f << LastError);

				Result["TimestampToken"] = fg_Move(TimestampToken);
			}

			co_return Result;
		}
	}

	NConcurrency::TCActorFunctor<NConcurrency::TCFuture<NEncoding::CEJsonSorted> ()> fg_SignFiles
		(
			NStr::CStr _FilePath
			, NContainer::CSecureByteVector _PrivateKey
			, NContainer::CByteVector _Certificate
			, EDigestType _Digest
			, CTimestampOptions _TimestampOptions
 		)
	{

		NStorage::TCSharedPointer<NAtomic::TCAtomic<bool>> pAborted = fg_Construct(false);

		return NConcurrency::g_ActorFunctor
			(
				NConcurrency::g_ActorSubscription(NConcurrency::fg_DirectCallActor()) / [pAborted] -> NConcurrency::TCFuture<void>
				{
					pAborted->f_Exchange(true);
					co_return {};
				}
			)
			/ [
				FilePath = fg_Move(_FilePath)
				, PrivateKey = fg_Move(_PrivateKey)
				, Certificate = fg_Move(_Certificate)
				, _Digest
				, TimestampOptions = fg_Move(_TimestampOptions)
				, pAborted
			]() mutable -> NConcurrency::TCFuture<NEncoding::CEJsonSorted>
			{
				if (!NFile::CFile::fs_IsPathAbsolute(FilePath))
					co_return DMibErrorInstance("Only absolute paths supported");

				auto BlockingActor = NConcurrency::fg_BlockingActor();
				auto SignParams = co_await
					(
						NConcurrency::g_Dispatch(BlockingActor) / [FilePath, pAborted]() mutable
						{
							CSignParams SignParams;
							SignParams.m_pAborted = pAborted;

							auto LinkAttributes = NFile::CFile::fs_GetAttributesOnLink(FilePath);
							bool bIsSymlinkRoot = (LinkAttributes & NFile::EFileAttrib_Link) != 0;
							auto TargetAttributes = bIsSymlinkRoot ? NFile::CFile::fs_GetAttributes(FilePath) : LinkAttributes;

							SignParams.m_bInputIsDirectory = !bIsSymlinkRoot && (TargetAttributes & NFile::EFileAttrib_Directory) != 0;

							NFile::CDirectoryManifestConfig ManifestConfig;
							ManifestConfig.m_Flags |= NFile::EDirectoryManifestConfigFlag::mc_DisableDigest;

							if (SignParams.m_bInputIsDirectory)
								ManifestConfig.m_Root = FilePath;
							else
							{
								ManifestConfig.m_Root = FilePath;
								ManifestConfig.m_IncludeWildcards = {{"", {}}};
							}

							ManifestConfig.f_Validate();

							SignParams.m_Manifest = NFile::CDirectoryManifest::fs_GetManifest
								(
									ManifestConfig
									, [&]
									{
										if (pAborted->f_Load(NAtomic::EMemoryOrder_Relaxed))
											DMibError("Signing aborted");
									}
								)
							;

							SignParams.m_RootPath = ManifestConfig.m_Root;

							return SignParams;
						}
					)
				;

				EDigestType DigestType = _Digest;
				if (DigestType == EDigestType_Automatic)
					DigestType = EDigestType_SHA512;

				if (DigestType != EDigestType_SHA256 && DigestType != EDigestType_SHA384 && DigestType != EDigestType_SHA512)
					co_return DMibErrorInstanceCryptography("Unsupported digest type for signing: {}"_f << (int32)DigestType);

				SignParams.m_DigestType = DigestType;
				SignParams.m_PrivateKey = fg_Move(PrivateKey);
				SignParams.m_Certificate = fg_Move(Certificate);
				SignParams.m_TimestampURLs = fg_Move(TimestampOptions.m_TimestampURLs);
				SignParams.m_TimestampTrustedCAs = fg_Move(TimestampOptions.m_TimestampTrustedCACertificates);

				co_return co_await fg_SignDetachedAsync(fg_Move(SignParams));
			}
		;
	}

	namespace
	{
		using namespace NStr;

		EDigestType fg_DigestTypeFromStr(NStr::CStr const &_DigestStr)
		{
			if (_DigestStr == "SHA512")
				return EDigestType_SHA512;
			if (_DigestStr == "SHA384")
				return EDigestType_SHA384;
			if (_DigestStr == "SHA256")
				return EDigestType_SHA256;

			return EDigestType_Automatic;
		}

		NContainer::CByteVector fg_VerifyCertificateAndExtractPublicKey
			(
				NContainer::CByteVector const &_CertificateData
				, NContainer::TCVector<NContainer::CByteVector> const &_TrustedCACertificates
			)
		{
			using namespace NBoringSSL;

			// Load the certificate to verify
			X509 *pCert = fg_LoadCertificate(_CertificateData);
			auto CleanupCert = g_OnScopeExit / [&]
				{
					X509_free(pCert);
				}
			;

			// Create a certificate store with the trusted CAs
			X509_STORE *pStore = X509_STORE_new();
			if (!pStore)
				DMibErrorCryptography(fg_GetExceptionStr("Failed to create X509 store"));

			auto CleanupStore = g_OnScopeExit / [&]
				{
					X509_STORE_free(pStore);
				}
			;

			// Add all trusted CA certificates to the store
			for (auto const &CACertData : _TrustedCACertificates)
			{
				X509 *pCACert = fg_LoadCertificate(CACertData);
				auto CleanupCA = g_OnScopeExit / [&]
					{
						// Note: X509_STORE_add_cert increments the reference count, so we still need to free
						X509_free(pCACert);
					}
				;

				ERR_clear_error();
				if (X509_STORE_add_cert(pStore, pCACert) != 1)
				{
					// It's okay if certificate already exists
					unsigned long Err = ERR_peek_last_error();
					if (ERR_GET_REASON(Err) != X509_R_CERT_ALREADY_IN_HASH_TABLE)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to add CA certificate to store"));
				}
			}

			// Create verification context
			X509_STORE_CTX *pCtx = X509_STORE_CTX_new();
			if (!pCtx)
				DMibErrorCryptography(fg_GetExceptionStr("Failed to create X509 store context"));

			auto CleanupCtx = g_OnScopeExit / [&]
				{
					X509_STORE_CTX_free(pCtx);
				}
			;

			// Initialize context for verification
			ERR_clear_error();
			if (X509_STORE_CTX_init(pCtx, pStore, pCert, nullptr) != 1)
				DMibErrorCryptography(fg_GetExceptionStr("Failed to initialize X509 store context"));

			// Enable partial chain verification to support self-signed certificates
			// This allows verification to succeed if the certificate itself is in the trusted store
			X509_STORE_CTX_set_flags(pCtx, X509_V_FLAG_PARTIAL_CHAIN);

			// Verify the certificate
			ERR_clear_error();
			int VerifyResult = X509_verify_cert(pCtx);
			if (VerifyResult != 1)
			{
				int nError = X509_STORE_CTX_get_error(pCtx);
				NStr::CStr ErrorStr = X509_verify_cert_error_string(nError);
				DMibErrorCryptography("Certificate chain verification failed: {}"_f << ErrorStr);
			}

			// Extract the public key from the verified certificate
			EVP_PKEY *pPublicKey = X509_get_pubkey(pCert);
			if (!pPublicKey)
				DMibErrorCryptography(fg_GetExceptionStr("Failed to extract public key from certificate"));

			auto CleanupKey = g_OnScopeExit / [&]
				{
					EVP_PKEY_free(pPublicKey);
				}
			;

			return fg_ConvertPublicKeyToDER(pPublicKey).f_ToInsecure();
		}

		struct CVerifyParams
		{
			NStr::CStr m_RootPath;
			NFile::CDirectoryManifest m_ExpectedManifest;
			NFile::CDirectoryManifest m_ActualManifest;
			NContainer::CByteVector m_PublicKey;
			NContainer::CByteVector m_Signature;
			NContainer::CByteVector m_TimestampToken;
			NContainer::TCVector<NContainer::CByteVector> m_TimestampTrustedCAs;
			EDigestType m_DigestType = EDigestType_Automatic;
			int64 m_ExpectedMessageLength = 0;
			NStorage::TCSharedPointer<NAtomic::TCAtomic<bool>> m_pAborted;
		};

		NFile::EFileAttrib fg_CheckedAttributes(NFile::EFileAttrib _Attributes)
		{
			return (_Attributes & (NFile::EFileAttrib_Directory | NFile::EFileAttrib_File | NFile::EFileAttrib_Link));
		}

		NStr::CStr fg_RelativePathName(NStr::CStr const &_String)
		{
			if (_String.f_IsEmpty())
				return NStr::gc_Str<"file">.m_Str;

			return _String;
		}

		NConcurrency::TCFuture<void> fg_VerifyDetachedAsync(CVerifyParams _Params)
		{
			co_await NConcurrency::fg_ContinueRunningOnActor(NConcurrency::fg_ConcurrentActorHighCPU());

			auto CaptureScope = co_await (NConcurrency::g_CaptureExceptions % "Exception while verifying files");

			using namespace NBoringSSL;

			for (auto const &ExpectedEntry : _Params.m_ExpectedManifest.m_Files)
			{
				auto const &RelativePath = _Params.m_ExpectedManifest.m_Files.fs_GetKey(ExpectedEntry);
				auto const *pActualEntry = _Params.m_ActualManifest.m_Files.f_FindEqual(RelativePath);

				if (!pActualEntry)
					co_return DMibErrorInstance("File missing from actual manifest: {}"_f << fg_RelativePathName(RelativePath));

				if (fg_CheckedAttributes(ExpectedEntry.m_Attributes) != fg_CheckedAttributes(pActualEntry->m_Attributes))
					co_return DMibErrorInstance("File attributes mismatch for {}"_f << fg_RelativePathName(RelativePath));

				if (ExpectedEntry.f_IsFile())
				{
					if (ExpectedEntry.m_Length != pActualEntry->m_Length)
						co_return DMibErrorInstance("File length mismatch for {}"_f << fg_RelativePathName(RelativePath));
				}
			}

			for (auto const &ActualEntry : _Params.m_ActualManifest.m_Files)
			{
				auto const &RelativePath = _Params.m_ActualManifest.m_Files.fs_GetKey(ActualEntry);
				auto const *pExpectedEntry = _Params.m_ExpectedManifest.m_Files.f_FindEqual(RelativePath);

				if (!pExpectedEntry)
					co_return DMibErrorInstance("Unexpected file found in directory: {}"_f << fg_RelativePathName(RelativePath));
			}

			auto pKey = fg_LoadPublicKeyFromDER(_Params.m_PublicKey.f_ToSecure());
			auto CleanupKey = g_OnScopeExit / [&]
				{
					if (pKey)
						EVP_PKEY_free(pKey);
				}
			;

			auto pDigest = fg_GetDigest(_Params.m_DigestType, pKey);

			ERR_clear_error();
			auto pCtx = EVP_MD_CTX_create();
			if (!pCtx)
				co_return DMibErrorInstanceCryptography(fg_GetExceptionStr("EVP_MD_CTX_create failed"));

			auto CleanupCtx = g_OnScopeExit / [&]
				{
					EVP_MD_CTX_destroy(pCtx);
				}
			;

			ERR_clear_error();
			if (EVP_DigestVerifyInit(pCtx, nullptr, pDigest, nullptr, pKey) != 1)
				co_return DMibErrorInstanceCryptography(fg_GetExceptionStr("EVP_DigestVerifyInit failed"));

			uint64 MessageLength = 0;

			auto fAddToDigest = [&](void const *_pData, mint _Len)
				{
					if (!_Len)
						return;

					MessageLength += _Len;

					ERR_clear_error();
					if (EVP_DigestVerifyUpdate(pCtx, _pData, _Len) != 1)
						DMibErrorCryptography(fg_GetExceptionStr("EVP_DigestVerifyUpdate failed"));
				}
			;

			auto fAddUInt64 = [&](uint64 _Value)
				{
					auto ValueLE = NMib::fg_ByteSwapLE(_Value);
					fAddToDigest(&ValueLE, sizeof(ValueLE));
				}
			;

			auto fAddString = [&](NStr::CStr const &_String)
				{
					fAddUInt64(uint64(_String.f_GetLen()));
					fAddToDigest(_String.f_GetStr(), _String.f_GetLen());
				}
			;

			for (auto const &ExpectedEntry : _Params.m_ExpectedManifest.m_Files)
			{
				if (_Params.m_pAborted->f_Load(NAtomic::EMemoryOrder_Relaxed))
					co_return DMibErrorInstance("Aborted");

				auto &FileName = ExpectedEntry.f_GetFileName();

				if (ExpectedEntry.f_IsFile())
				{
					fAddUInt64(ExpectedEntry.m_Length);

					auto FileGenerator = NFile::fg_ReadFileGenerator(NFile::CReadFileGeneratorParams{.m_Path = _Params.m_RootPath / FileName});

					for (auto iChunk = co_await fg_Move(FileGenerator).f_GetPipelinedIterator(); iChunk; co_await ++iChunk)
					{
						if (_Params.m_pAborted->f_Load(NAtomic::EMemoryOrder_Relaxed))
							co_return DMibErrorInstance("Aborted");

						auto const &Chunk = *iChunk;
						fAddToDigest(Chunk.f_GetArray(), Chunk.f_GetLen());
					}
				}
			}

			auto ManifestJson = _Params.m_ExpectedManifest.f_ToJson();
			auto ManifestJsonStr = ManifestJson.f_ToString(nullptr);
			fAddString(ManifestJsonStr);

			if (MessageLength != uint64(_Params.m_ExpectedMessageLength))
				co_return DMibErrorInstance("Message length mismatch: expected {}, got {}"_f << _Params.m_ExpectedMessageLength << MessageLength);

			ERR_clear_error();
			int nResult = EVP_DigestVerifyFinal(pCtx, _Params.m_Signature.f_GetArray(), _Params.m_Signature.f_GetLen());
			if (nResult & ~0x01)
				co_return DMibErrorInstanceCryptography(fg_GetExceptionStr("EVP_DigestVerifyFinal failed"));

			if (nResult != 1)
				co_return DMibErrorInstance("Signature verification failed");

			// Verify timestamp if present
			if (!_Params.m_TimestampToken.f_IsEmpty())
			{
				// Parse timestamp to get the hash algorithm used by the TSA
				CTimestampInfo TimestampInfo = fg_ParseTimestampToken(_Params.m_TimestampToken);

				// Compute digest of the signature using the algorithm specified in the timestamp
				// Note: Some TSAs use their own preferred algorithm regardless of what was requested
				NContainer::CByteVector SignatureDigest;
				switch (TimestampInfo.m_MessageImprintAlgorithm)
				{
				case EDigestType_SHA256:
					{
						CHash_SHA256 Hash;
						Hash.f_AddData(_Params.m_Signature.f_GetArray(), _Params.m_Signature.f_GetLen());
						auto Digest = Hash.f_GetDigest();
						SignatureDigest = NContainer::CByteVector((unsigned char const *)&Digest, sizeof(Digest));
					}
					break;
				case EDigestType_SHA384:
					{
						CHash_SHA384 Hash;
						Hash.f_AddData(_Params.m_Signature.f_GetArray(), _Params.m_Signature.f_GetLen());
						auto Digest = Hash.f_GetDigest();
						SignatureDigest = NContainer::CByteVector((unsigned char const *)&Digest, sizeof(Digest));
					}
					break;
				case EDigestType_SHA512:
					{
						CHash_SHA512 Hash;
						Hash.f_AddData(_Params.m_Signature.f_GetArray(), _Params.m_Signature.f_GetLen());
						auto Digest = Hash.f_GetDigest();
						SignatureDigest = NContainer::CByteVector((unsigned char const *)&Digest, sizeof(Digest));
					}
					break;
				default:
					co_return DMibErrorInstance("Unsupported digest type in timestamp: {}"_f << (int32)TimestampInfo.m_MessageImprintAlgorithm);
				}

				// Verify timestamp token: parse, verify signature, and validate imprint
				fg_VerifyTimestamp
					(
						_Params.m_TimestampToken
						, SignatureDigest
						, TimestampInfo.m_MessageImprintAlgorithm
						, _Params.m_TimestampTrustedCAs
						, true // Require timeStamping EKU
					)
				;
			}

			co_return {};
		}
	}

	NConcurrency::TCActorFunctor<NConcurrency::TCFuture<void> ()> fg_VerifyFiles
		(
			NStr::CStr _FilePath
			, NEncoding::CEJsonSorted _SignatureJson
			, NContainer::TCVector<NContainer::CByteVector> _TrustedCACertificates
			, CVerifyOptions _VerifyOptions
		)
	{
		NStorage::TCSharedPointer<NAtomic::TCAtomic<bool>> pAborted = fg_Construct(false);

		return NConcurrency::g_ActorFunctor
			(
				NConcurrency::g_ActorSubscription(NConcurrency::fg_DirectCallActor()) / [pAborted] -> NConcurrency::TCFuture<void>
				{
					pAborted->f_Exchange(true);
					co_return {};
				}
			)
			/
			[
				FilePath = fg_Move(_FilePath)
				, SignatureJson = fg_Move(_SignatureJson)
				, TrustedCACertificates = fg_Move(_TrustedCACertificates)
				, VerifyOptions = fg_Move(_VerifyOptions)
				, pAborted
			]
			() mutable -> NConcurrency::TCFuture<void>
			{
				using namespace NStr;

				auto const *pDigestAlgorithm = SignatureJson.f_GetMember("DigestAlgorithm");
				if (!pDigestAlgorithm || !pDigestAlgorithm->f_IsString())
					co_return DMibErrorInstance("Missing or invalid DigestAlgorithm in signature JSON");

				auto const *pInputType = SignatureJson.f_GetMember("InputType");
				if (!pInputType || !pInputType->f_IsString())
					co_return DMibErrorInstance("Missing or invalid InputType in signature JSON");

				auto const *pManifestJson = SignatureJson.f_GetMember("Manifest");
				if (!pManifestJson)
					co_return DMibErrorInstance("Missing Manifest in signature JSON");

				auto const *pSignature = SignatureJson.f_GetMember("Signature");
				if (!pSignature || !pSignature->f_IsBinary())
					co_return DMibErrorInstance("Missing or invalid Signature in signature JSON");

				auto const *pMessageLength = SignatureJson.f_GetMember("MessageLength");
				if (!pMessageLength || !pMessageLength->f_IsInteger())
					co_return DMibErrorInstance("Missing or invalid MessageLength in signature JSON");

				auto const *pCertificate = SignatureJson.f_GetMember("Certificate");
				if (!pCertificate || !pCertificate->f_IsBinary())
					co_return DMibErrorInstance("Missing or invalid Certificate in signature JSON");

				NContainer::CByteVector PublicKey;
				{
					auto CaptureScope = co_await (NConcurrency::g_CaptureExceptions % "Failed to verify certificate");
					PublicKey = fg_VerifyCertificateAndExtractPublicKey(pCertificate->f_Binary(), TrustedCACertificates);
				}

				EDigestType DigestType = fg_DigestTypeFromStr(pDigestAlgorithm->f_String());
				if (DigestType == EDigestType_Automatic)
					co_return DMibErrorInstance("Unknown digest algorithm: {}"_f << pDigestAlgorithm->f_String());

				bool bIsDirectory = pInputType->f_String() == "Directory";

				if (!NFile::CFile::fs_IsPathAbsolute(FilePath))
					co_return DMibErrorInstance("Only absolute paths supported");

				auto BlockingActor = NConcurrency::fg_BlockingActor();
				auto VerifyParams = co_await
					(
						NConcurrency::g_Dispatch(BlockingActor) / [FilePath, pManifestJson, bIsDirectory, pAborted]() mutable
						{
							CVerifyParams VerifyParams;
							VerifyParams.m_pAborted = pAborted;

							VerifyParams.m_ExpectedManifest = NFile::CDirectoryManifest::fs_FromJson(*pManifestJson);

							auto LinkAttributes = NFile::CFile::fs_GetAttributesOnLink(FilePath);
							bool bIsSymlinkRoot = (LinkAttributes & NFile::EFileAttrib_Link) != 0;
							auto TargetAttributes = bIsSymlinkRoot ? NFile::CFile::fs_GetAttributes(FilePath) : LinkAttributes;

							bool bActualIsDirectory = !bIsSymlinkRoot && (TargetAttributes & NFile::EFileAttrib_Directory) != 0;

							if (bIsDirectory != bActualIsDirectory)
								DMibError("InputType mismatch: expected {}, got {}"_f << (bIsDirectory ? "Directory" : "File") << (bActualIsDirectory ? "Directory" : "File"));

							NFile::CDirectoryManifestConfig ManifestConfig;
							ManifestConfig.m_Flags |= NFile::EDirectoryManifestConfigFlag::mc_DisableDigest;

							if (bActualIsDirectory)
								ManifestConfig.m_Root = FilePath;
							else
							{
								ManifestConfig.m_Root = FilePath;
								ManifestConfig.m_IncludeWildcards = {{"", {}}};
							}

							ManifestConfig.f_Validate();

							VerifyParams.m_ActualManifest = NFile::CDirectoryManifest::fs_GetManifest
								(
									ManifestConfig
									, [&]
									{
										if (pAborted->f_Load(NAtomic::EMemoryOrder_Relaxed))
											DMibError("Verification aborted");
									}
								)
							;

							VerifyParams.m_RootPath = ManifestConfig.m_Root;

							return VerifyParams;
						}
					)
				;

				VerifyParams.m_DigestType = DigestType;
				VerifyParams.m_PublicKey = fg_Move(PublicKey);
				VerifyParams.m_Signature = pSignature->f_Binary();
				VerifyParams.m_ExpectedMessageLength = pMessageLength->f_Integer();

				// Extract timestamp token if present
				auto const *pTimestampToken = SignatureJson.f_GetMember("TimestampToken");
				bool bHasTimestamp = pTimestampToken && pTimestampToken->f_IsBinary();

				// Check if timestamp is required
				if (fg_IsSet(VerifyOptions.m_Flags, EVerifyFlag::mc_RequireTimestamp) && !bHasTimestamp)
					co_return DMibErrorInstance("Timestamp required but not present in signature");

				if (bHasTimestamp)
				{
					VerifyParams.m_TimestampToken = pTimestampToken->f_Binary();
					VerifyParams.m_TimestampTrustedCAs = VerifyOptions.m_TimestampTrustedCACertificates;
				}

				co_return co_await fg_VerifyDetachedAsync(fg_Move(VerifyParams));
			}
		;
	}
}
