// Copyright © 2018 Nonna Holding AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Container/RegistryMixed>
#include <Mib/Network/SSL>
#include <Mib/Test/Exception>
#include <Mib/Cryptography/EncryptedStream>

#define DMibCryptographyErrorInstance(d_Description) NMib::NCryptography::CExceptionCryptography("CExceptionCryptography", d_Description, false)

namespace
{
	enum ETesting
	{
		ETesting_0,
		ETesting_1,
	};

	using namespace NMib::NStream;
	using namespace NMib::NContainer;
	using namespace NMib::NStr;
	using namespace NMib::NTest;
	using namespace NMib::NCryptography;
	using namespace NMib::NNetwork;

	class CEncryptedStream_Tests : public CTest
	{
	public:

		void f_DoTests()
		{

			DMibTestCategory("Encrypted Stream")
			{
				static uint8 const *KeyBytes = (uint8 const *)"abcdefghijklmnopqrstuvwxyz012345abcdefghijklmnopqrstuvwxyz012345";
				mint KeyBytesLen = fg_StrLen(KeyBytes);
				CStr ClearText = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";
				CByteVector Buffer;
				NMib::NNetwork::CKeyExpansion KeyExpansion{CSecureByteVector(KeyBytes, KeyBytesLen), {}};

				DMibTestSuite("Secure byte vector Key and IV")
				{
					CBinaryStreamMemory<> Stream;
					TCBinaryStream_Encrypted<CBinaryStream *> EncryptedStream(KeyExpansion.f_GetKeyIV(), ESSLDigest_SHA512, KeyExpansion.f_GetHMACKey(ESSLDigest_SHA512));

					EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Write);
					EncryptedStream << ClearText;
					EncryptedStream.f_Close();

					CStr Result;
					EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Read);
					EncryptedStream >> Result;
					EncryptedStream.f_Close();

					DMibExpect(Result, ==, ClearText);

					Stream.f_SetPosition(32);
					Stream << '0';

					DMibExpectExceptionType(EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Read), CExceptionCryptography);
					EncryptedStream.f_Close();
				};

				DMibTestSuite("Password and salt")
				{
					static const char *KeyBytes = "abcdefghijk";
					CSecureByteVector Salt{0, 1, 2, 3};
					CKeyExpansion KeyExpansion{KeyBytes, Salt, CKeyDerivationSettings_Scrypt{}, {}};

					CBinaryStreamMemory<> Stream;
					TCBinaryStream_Encrypted<CBinaryStream *> EncryptedStream(KeyExpansion.f_GetKeyIV(), ESSLDigest_SHA512, KeyExpansion.f_GetHMACKey(ESSLDigest_SHA512));

					EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Write);
					EncryptedStream << ClearText;
					EncryptedStream.f_Close();

					CStr Result;
					EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Read);
					EncryptedStream >> Result;
					EncryptedStream.f_Close();

					DMibExpect(Result, ==, ClearText);
				};

				DMibTestSuite("Detect tampering")
				{
					CBinaryStreamMemory<> Stream;
					TCBinaryStream_Encrypted<CBinaryStream *> EncryptedStream(KeyExpansion.f_GetKeyIV(), ESSLDigest_SHA512, KeyExpansion.f_GetHMACKey(ESSLDigest_SHA512));

					EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Write);
					EncryptedStream << ClearText;
					EncryptedStream.f_Close();

					CStr Result;
					EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Read);
					EncryptedStream >> Result;
					EncryptedStream.f_Close();

					DMibExpect(Result, ==, ClearText);

					Stream.f_SetPosition(32);
					Stream << '0';

					DMibExpectExceptionType(EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Read), CExceptionCryptography);
					EncryptedStream.f_Close();
				};

				DMibTestSuite("Changing buffer size")
				{
					CBinaryStreamMemory<> Stream;
					TCBinaryStream_Encrypted<CBinaryStream *> EncryptedStream(KeyExpansion.f_GetKeyIV(), ESSLDigest_SHA512, KeyExpansion.f_GetHMACKey(ESSLDigest_SHA512));

					// Unfortunately, we cannot give these errors until the stream is opened and we have initialized the cipher.
					EncryptedStream.f_SetBufferSize(1);
					DMibExpectException
						(
						 	EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Write)
						 	, DMibCryptographyErrorInstance("Buffer size cannot be smaller than cipher block size: 16")
						)
					;

					DMibExpectException(EncryptedStream.f_SetBufferSize(17), DMibCryptographyErrorInstance("Buffer size must be a power of 2"));

					EncryptedStream.f_SetBufferSize(16);
					EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Write);

					DMibExpectException(EncryptedStream.f_SetBufferSize(16), DMibCryptographyErrorInstance("Cannot resize buffer on an open stream"));

					EncryptedStream << ClearText;
					EncryptedStream.f_Close();

					CStr Result;
					EncryptedStream.f_SetBufferSize(16);
					EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Read);
					EncryptedStream >> Result;
					EncryptedStream.f_Close();

					DMibExpect(Result, ==, ClearText);
				};

				DMibTestSuite("Pure write")
				{
					CBinaryStreamMemory<> Stream;
					TCBinaryStream_Encrypted<CBinaryStream *> EncryptedStream(KeyExpansion.f_GetKeyIV(), ESSLDigest_SHA512, KeyExpansion.f_GetHMACKey(ESSLDigest_SHA512));

					EncryptedStream.f_SetBufferSize(16);
					EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Write);
					EncryptedStream.f_FeedBytes(ClearText.f_GetStr(), 25);
					auto Pos = EncryptedStream.f_GetPosition();
					DMibExpect(Pos, ==, 25);
					EncryptedStream.f_SetPosition(Pos); // No-op, this should work
					DMibExpectException(EncryptedStream.f_SetPosition(16), DMibCryptographyErrorInstance("Stream does not support positioning during write"));
					DMibExpectException(EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 1), DMibCryptographyErrorInstance("Stream not opened for read"));

					EncryptedStream.f_Close();
					DMibExpectException(EncryptedStream.f_FeedBytes(ClearText.f_GetStr(), 1), DMibCryptographyErrorInstance("Stream not opened for write"));
				};

				DMibTestSuite("Random access reads")
				{
					CBinaryStreamMemory<> Stream;
					TCBinaryStream_Encrypted<CBinaryStream *> EncryptedStream(KeyExpansion.f_GetKeyIV(), ESSLDigest_SHA512, KeyExpansion.f_GetHMACKey(ESSLDigest_SHA512));

					EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Write);
					EncryptedStream.f_FeedBytes(ClearText.f_GetStr(), ClearText.f_GetLen());
					EncryptedStream.f_Close();

					EncryptedStream.f_SetBufferSize(16);
					EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Read);

					// First positions matching block boundaries
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(16), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() , 16), ==, 0);
					EncryptedStream.f_SetPosition(48);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 48, 16), ==, 0);
					EncryptedStream.f_SetPosition(32);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 32, 16), ==, 0);
					EncryptedStream.f_SetPosition(16);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 16, 16), ==, 0);

					// First positions matching block boundaries
					EncryptedStream.f_SetPosition(5);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 5, 16), ==, 0);
					EncryptedStream.f_SetPosition(39);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 39, 16), ==, 0);
					EncryptedStream.f_SetPosition(101);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 101, 16), ==, 0);
					EncryptedStream.f_SetPosition(55);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 55, 16), ==, 0);

					EncryptedStream.f_SetPosition(EncryptedStream.f_GetLength() - 8);
					DMibExpectException(EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 32), DMibCryptographyErrorInstance("Read past end of file"));
					EncryptedStream.f_SetPosition(EncryptedStream.f_GetLength() - 15);
					DMibExpectException(EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16), DMibCryptographyErrorInstance("Read past end of file"));
					EncryptedStream.f_SetPosition(EncryptedStream.f_GetLength() - 1);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 1);
					DMibExpect(Buffer[0], ==, '.');


					DMibExpectException(EncryptedStream.f_FeedBytes(ClearText.f_GetStr(), 1), DMibCryptographyErrorInstance("Stream not opened for write"));

					EncryptedStream.f_Close();

					DMibExpectException(EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 1), DMibCryptographyErrorInstance("Stream not opened for read"));
				};

				DMibTestSuite("First write, then random access reads")
				{
					CBinaryStreamMemory<> Stream;
					TCBinaryStream_Encrypted<CBinaryStream *> EncryptedStream(KeyExpansion.f_GetKeyIV(), ESSLDigest_SHA512, KeyExpansion.f_GetHMACKey(ESSLDigest_SHA512));

					EncryptedStream.f_SetBufferSize(16);
					EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Read | NMib::NFile::EFileOpen_Write);
					EncryptedStream.f_FeedBytes(ClearText.f_GetStr(), ClearText.f_GetLen());

					// This time we don't close, just set the postion. That should convert the stream to a read only stream.

					// First positions matching block boundaries
					EncryptedStream.f_SetPosition(96);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(16), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 96, 16), ==, 0);
					EncryptedStream.f_SetPosition(48);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 48, 16), ==, 0);
					EncryptedStream.f_SetPosition(32);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 32, 16), ==, 0);
					EncryptedStream.f_SetPosition(16);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 16, 16), ==, 0);

					// First positions matching block boundaries
					EncryptedStream.f_SetPosition(5);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 5, 16), ==, 0);
					EncryptedStream.f_SetPosition(39);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 39, 16), ==, 0);
					EncryptedStream.f_SetPosition(101);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 101, 16), ==, 0);
					EncryptedStream.f_SetPosition(55);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16);
					DMibExpect(NMib::NMemory::fg_MemCmp(Buffer.f_GetArray(), (uint8 *)ClearText.f_GetStr() + 55, 16), ==, 0);

					EncryptedStream.f_SetPosition(EncryptedStream.f_GetLength() - 8);
					DMibExpectException(EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 32), DMibCryptographyErrorInstance("Read past end of file"));
					EncryptedStream.f_SetPosition(EncryptedStream.f_GetLength() - 15);
					DMibExpectException(EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 16), DMibCryptographyErrorInstance("Read past end of file"));
					EncryptedStream.f_SetPosition(EncryptedStream.f_GetLength() - 1);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 1);
					DMibExpect(Buffer[0], ==, '.');


					DMibExpectException(EncryptedStream.f_FeedBytes(ClearText.f_GetStr(), 1), DMibCryptographyErrorInstance("Stream not opened for write"));

					EncryptedStream.f_Close();

					DMibExpectException(EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 1), DMibCryptographyErrorInstance("Stream not opened for read"));
				};

				DMibTestSuite("Streams shorter than crypto block size")
				{
					CBinaryStreamMemory<> Stream;
					TCBinaryStream_Encrypted<CBinaryStream *> EncryptedStream(KeyExpansion.f_GetKeyIV(), ESSLDigest_SHA512, KeyExpansion.f_GetHMACKey(ESSLDigest_SHA512));

					EncryptedStream.f_SetBufferSize(16);
					EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Read | NMib::NFile::EFileOpen_Write);
					EncryptedStream.f_FeedBytes(ClearText.f_GetStr(), 1);
					EncryptedStream.f_Close();

					EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Read);
					EncryptedStream.f_ConsumeBytes(Buffer.f_GetArray(), 1);
					DMibExpect(Buffer[0], ==, ClearText[0]);
					EncryptedStream.f_Close();
				};
				DMibTestSuite("All Ciphers")
				{
					TCMap<ESSLCrypto, CStr> Ciphers =
						{
							{ESSLCrypto_AES_256_CBC, "ESSLCrypto_AES_256_CBC"}
							, {ESSLCrypto_AES_128_CBC, "ESSLCrypto_AES_128_CBC"}
							, {ESSLCrypto_AES_256_OFB, "ESSLCrypto_AES_256_OFB"}
							, {ESSLCrypto_AES_128_OFB, "ESSLCrypto_AES_128_OFB"}
							, {ESSLCrypto_DES_EDE3_CBC, "ESSLCrypto_DES_EDE3_CBC"}
							, {ESSLCrypto_AES_256_ECB, "ESSLCrypto_AES_256_ECB"}
							, {ESSLCrypto_AES_128_ECB, "ESSLCrypto_AES_128_ECB"}
						}
					;

					auto fGetHMAC = [](ESSLCrypto _Crypto)
						{
							switch (_Crypto)
							{
							case ESSLCrypto_AES_128_CBC:
							case ESSLCrypto_AES_128_OFB:
							case ESSLCrypto_AES_128_ECB:
								return ESSLDigest_SHA1;
							case ESSLCrypto_AES_256_CBC:
							case ESSLCrypto_AES_256_OFB:
							case ESSLCrypto_AES_256_ECB:
								return ESSLDigest_SHA256;
							case ESSLCrypto_DES_EDE3_CBC:
								return ESSLDigest_SHA1;
							}
							DMibNeverGetHere;
							return ESSLDigest_SHA256;
						}
					;

					TCMap<ESSLCrypto, CByteVector> Encrypted;
					for (auto const &Cipher : Ciphers)
					{
						DMibTestPath(CStr::CFormat("Cipher {}") << Cipher);

						ESSLCrypto const CipherKey = Ciphers.fs_GetKey(Cipher);

						bool bCanChangePosition = CipherKey != ESSLCrypto_AES_256_OFB && CipherKey != ESSLCrypto_AES_128_OFB;

						NMib::NNetwork::CKeyExpansion KeyExpansion{CSecureByteVector(KeyBytes, KeyBytesLen), {}};

						auto HMAC = fGetHMAC(CipherKey);
						auto HMACKey = KeyExpansion.f_GetHMACKey(HMAC);

						CBinaryStreamMemory<> Stream;
						TCBinaryStream_Encrypted<CBinaryStream *> EncryptedStream(KeyExpansion.f_GetKeyIV(CipherKey), HMAC, HMACKey);

						EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Write);
						EncryptedStream << ClearText;
						EncryptedStream.f_Close();
						Encrypted[CipherKey] = Stream.f_GetVector();
						{
							DMibTestPath("Whole");
							CStr Result;
							EncryptedStream.f_Open(&Stream, NMib::NFile::EFileOpen_Read);
							EncryptedStream >> Result;
							EncryptedStream.f_Close();
							DMibExpect(Result, ==, ClearText);
						}
						{
							DMibTestPath("Restart");
							CStr Result;
							TCBinaryStream_Encrypted<CBinaryStream *> DecryptStream(KeyExpansion.f_GetKeyIV(CipherKey), HMAC, HMACKey);
							DecryptStream.f_SetBufferSize(16);
							DecryptStream.f_Open(&Stream, NMib::NFile::EFileOpen_Read);
							DecryptStream >> Result;
							DecryptStream.f_SetPosition(0);
							DecryptStream >> Result;
							DecryptStream.f_Close();
							DMibExpect(Result, ==, ClearText);
						}
						{
							DMibTestPath("Seek");
							CStr Result;
							TCBinaryStream_Encrypted<CBinaryStream *> DecryptStream(KeyExpansion.f_GetKeyIV(CipherKey), HMAC, HMACKey);
							DecryptStream.f_SetBufferSize(16);
							DecryptStream.f_Open(&Stream, NMib::NFile::EFileOpen_Read);
							DecryptStream >> Result;
							DecryptStream.f_SetPosition(4 + 22);
							CStr PartialResult;
							mint nPartialChars = ClearText.f_GetLen() - 22;
							if (bCanChangePosition)
							{
								DecryptStream.f_ConsumeBytes(PartialResult.f_GetStr(nPartialChars + 1), nPartialChars);
								PartialResult[nPartialChars] = 0;
								DecryptStream.f_Close();
								DMibExpect(PartialResult, ==, ClearText.f_Extract(22));
							}
							else
							{
								DMibExpectException
									(
									 	DecryptStream.f_ConsumeBytes(PartialResult.f_GetStr(nPartialChars + 1), nPartialChars)
									 	, DMibCryptographyErrorInstance("Crypto does not support random read access")
									)
								;
							}
						}
					}
					for (auto const &Cipher1 : Ciphers)
					{
						for (auto const &Cipher2 : Ciphers)
						{
							if (Cipher1 == Cipher2)
								continue;

							DMibTestPath(CStr::CFormat("Cipher {} differs from Cipher {}") << Cipher1 << Cipher2);
							DMibExpect(Encrypted[Ciphers.fs_GetKey(Cipher1)], !=, Encrypted[Ciphers.fs_GetKey(Cipher2)]);
						};
					};
				};
			};
		}
	};

	DMibTestRegister(CEncryptedStream_Tests, Malterlib::Cryptography);
}



