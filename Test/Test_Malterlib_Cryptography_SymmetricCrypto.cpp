// Copyright © 2015 Hansoft AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Network/SSL>
#include <Mib/Test/Exception>
#include <Mib/Cryptography/Certificate>
#include <Mib/Cryptography/SymmetricCrypto>

using namespace NMib;
using namespace NMib::NStr;
using namespace NMib::NContainer;
using namespace NMib::NCryptography;

class CSymmetricCrypto_Tests : public NMib::NTest::CTest
{
public:
	CSecureByteVector f_GetRandomBuffer(mint _Len, uint32 _Seed)
	{
		CSecureByteVector Buffer;
		Buffer.f_SetLen(_Len);
		NMisc::CRandomShiftRNG Rng{_Seed};
		for (auto &Char : Buffer)
			Char = Rng.f_GetValue<uint8>();
		return Buffer;
	}

	void f_DoTests()
	{
		DMibTestSuite("EncryptAES")
		{
			CStrSecure Password("MalterlibPasswordTest");

			CSecureByteVector Salt = f_GetRandomBuffer(8, 1);

			CEncryptAES EncryptAES(CEncryptKeyIV::fs_GenerateKeyIV(Password, Salt, CKeyDerivationSettings_PKCS5_Deprecated{}));

			CByteVector PlainText;
			CByteVector Decrypted;
			CByteVector Encrypted;

			PlainText = f_GetRandomBuffer(32, 7).f_ToInsecure();

			uint32 EncryptedLen = EncryptAES.f_Encrypt(PlainText.f_GetArray(), PlainText.f_GetLen(), Encrypted.f_GetArray(32));
			uint32 DecryptedLen = EncryptAES.f_Decrypt(Encrypted.f_GetArray(), Encrypted.f_GetLen(), Decrypted.f_GetArray(32));

			DMibExpect(EncryptedLen, ==, DecryptedLen);
			DMibExpect(Decrypted, ==, PlainText);
			DMibExpect(Encrypted, !=, PlainText);
			DMibExpect(Decrypted, !=, Encrypted);

			{
				DMibTestPath("IncorrectPassword");
				CStrSecure IncorrectPassword("MalterlibPasswordTest2");
				CEncryptAES EncryptAES1(CEncryptKeyIV::fs_GenerateKeyIV(IncorrectPassword, Salt, CKeyDerivationSettings_PKCS5_Deprecated{}));
				EncryptAES1.f_Decrypt(Encrypted.f_GetArray(), Encrypted.f_GetLen(), Decrypted.f_GetArray());
				DMibExpect(Decrypted, !=, PlainText);
			}

			{
				DMibTestPath("IncorrectSalt");
				CSecureByteVector IncorrectSalt = f_GetRandomBuffer(8, 2);

				CEncryptAES EncryptAES2(CEncryptKeyIV::fs_GenerateKeyIV(Password, IncorrectSalt, CKeyDerivationSettings_PKCS5_Deprecated{}));
				EncryptAES2.f_Decrypt(Encrypted.f_GetArray(), Encrypted.f_GetLen(), Decrypted.f_GetArray());
				DMibExpect(Decrypted, !=, PlainText);
			}

			{
				DMibTestPath("Unaligned Plaintext");
				CByteVector Unaligned;
				Unaligned.f_SetLen(14);

				CEncryptAES EncryptAES3(CEncryptKeyIV::fs_GenerateKeyIV(Password, Salt, CKeyDerivationSettings_PKCS5_Deprecated{}));

				DMibTest
					(
						DMibExpr(TCThrowsException<NException::CException>())
						== DMibLExpr(EncryptAES3.f_Encrypt(Unaligned.f_GetArray(), Unaligned.f_GetLen(), Encrypted.f_GetArray(32)))
					)
				;
			}

			{
				DMibTestPath("Compare with OpenSSL enc");

				uint8 EncryptedByOpenSSL[] =
					{
						0x7e, 0x26, 0x44, 0x27, 0x23, 0x58, 0xfd, 0x32, 0xfa, 0x46, 0x80, 0xdc, 0xc0, 0x99, 0x45, 0x03,
						0x0d, 0x87, 0x20, 0xfc, 0x40, 0x5e, 0xb9, 0xd6, 0xed, 0xb9, 0x61, 0xc3, 0x98, 0x63, 0x58, 0xe8
					}
				;

				CByteVector EncryptedOpenSSL;
				EncryptedOpenSSL.f_SetLen(32);
				NMemory::fg_MemCopy(EncryptedOpenSSL.f_GetArray(), EncryptedByOpenSSL, 32);

				CByteVector ToEncrypt;
				ToEncrypt.f_SetLen(32);
				NMemory::fg_MemClear(ToEncrypt.f_GetArray(), ToEncrypt.f_GetLen());

				NStr::CStrSecure OpenSSLPassword("ABCDEFGH");
				CEncryptAES EncryptAES4
					(
						CEncryptKeyIV::fs_GenerateKeyIV(OpenSSLPassword, {}, CKeyDerivationSettings_PKCS5_Deprecated{EDigestType_SHA256, 1}, ECryptoType_AES_256_CBC)
					)
				;

				EncryptAES4.f_Encrypt(ToEncrypt.f_GetArray(), ToEncrypt.f_GetLen(), Encrypted.f_GetArray());
				DMibExpect(EncryptedOpenSSL, ==, Encrypted);

				EncryptAES4.f_Decrypt(EncryptedOpenSSL.f_GetArray(), EncryptedOpenSSL.f_GetLen(), Decrypted.f_GetArray());
				DMibExpect(Decrypted, ==, ToEncrypt);
			}
		};

		DMibTestSuite("Incremental Encrypt")
		{
			CStrSecure Password("MalterlibPasswordTest");
			// We use this buffer for both Key and IV
			CSecureByteVector Buffer
				{
					0x7e, 0x26, 0x44, 0x27, 0x23, 0x58, 0xfd, 0x32, 0xfa, 0x46, 0x80, 0xdc, 0xc0, 0x99, 0x45, 0x03,
					0x0d, 0x87, 0x20, 0xfc, 0x40, 0x5e, 0xb9, 0xd6, 0xed, 0xb9, 0x61, 0xc3, 0x98, 0x63, 0x58, 0xe8
				}
			;
			CSecureByteVector WrongBuffer
				{
					0x7e, 0x26, 0x44, 0x22, 0x32, 0x58, 0xfd, 0x32, 0xfa, 0x46, 0x80, 0xdc, 0xc0, 0x99, 0x45, 0x03,
					0x0d, 0x87, 0x20, 0xfc, 0x40, 0x5e, 0xb9, 0xd6, 0xed, 0xb9, 0x61, 0xc3, 0x98, 0x63, 0x58, 0xe8
				}
			;

			CSecureByteVector Salt = f_GetRandomBuffer(8, 3);

			CByteVector PlainText;
			CByteVector Decrypted;
			CByteVector Encrypted;
			uint32 EncryptedLen;
			uint32 DecryptedLen;
			uint32 BlockSize;
			// Use multiple lengths: small single block, around the block size border, around two blocks, around the buffer length +/- block size, huge buffer, and
			// finally a value that is suitable for the rest of the tests
			int const Lengths[] = { 1, 2, 14, 15, 16, 17, 25, 31, 33, 8192 - 17, 8192 - 16 , 8192 - 15, 8192, 8193, 8192 + 15, 8192 + 16, 8192 + 17, 55555, 32 };

			for (auto Length : Lengths)
			{
				DMibTestPath(fg_Format("Buffer length: {}", Length));
				PlainText = f_GetRandomBuffer(Length, 8).f_ToInsecure();
				auto KeyIV = CEncryptKeyIV::fs_GenerateKeyIV(Password, Salt, CKeyDerivationSettings_PKCS5_Deprecated{});
				CIncrementalEncrypt EncryptAES(ECryptoFlags_Encrypt | ECryptoFlags_UsePadding, KeyIV);
				CIncrementalEncrypt DecryptAES(ECryptoFlags_Decrypt | ECryptoFlags_UsePadding, KeyIV);

				BlockSize = CEncryptKeyIV::fs_GetBlockSize(ECryptoType_AES_256_CBC);
				EncryptedLen = EncryptAES.f_Encrypt(PlainText.f_GetArray(), PlainText.f_GetLen(), Encrypted.f_GetArray(PlainText.f_GetLen() + BlockSize));
				EncryptedLen += EncryptAES.f_FinalizePaddedEncrypt(Encrypted.f_GetArray() + EncryptedLen, Encrypted.f_GetLen() - EncryptedLen);

				DecryptedLen = DecryptAES.f_Decrypt(Encrypted.f_GetArray(), EncryptedLen, Decrypted.f_GetArray(EncryptedLen + BlockSize));
				DecryptedLen += DecryptAES.f_FinalizePaddedDecrypt(Decrypted.f_GetArray() + DecryptedLen, Decrypted.f_GetLen() - DecryptedLen);
				Decrypted.f_SetLen(DecryptedLen);

				DMibExpect(EncryptedLen, ==, (DecryptedLen + BlockSize) / BlockSize * BlockSize);
				DMibExpect(Decrypted, ==, PlainText);
				DMibExpect(Encrypted, !=, PlainText);
				DMibExpect(Decrypted, !=, Encrypted);

				if (EncryptedLen > BlockSize)
				{
					// Check that we, after a re-initialize, can decrypt and finalize the last block to get the correct length
					CSecureByteVector IV;
					NMemory::fg_MemCopy(IV.f_GetArray(BlockSize), Encrypted.f_GetArray() + EncryptedLen - 2 * BlockSize, BlockSize);
					CIncrementalEncrypt DecryptAES2(ECryptoFlags_Decrypt | ECryptoFlags_UsePadding, CEncryptKeyIV{KeyIV.m_Key, IV});
					DecryptedLen = DecryptAES2.f_Decrypt(Encrypted.f_GetArray() + EncryptedLen - BlockSize, BlockSize, Decrypted.f_GetArray(BlockSize * 2));
					DecryptedLen += DecryptAES2.f_FinalizePaddedDecrypt(Decrypted.f_GetArray() + DecryptedLen, Decrypted.f_GetLen() - DecryptedLen);
					DMibExpect(DecryptedLen, ==, Length % BlockSize);
				}

			}
			{
				DMibTestPath("IncorrectPassword");
				CStrSecure IncorrectPassword("MalterlibPasswordTest2");
				auto KeyIV = CEncryptKeyIV::fs_GenerateKeyIV(IncorrectPassword, Salt, CKeyDerivationSettings_PKCS5_Deprecated{});
				CIncrementalEncrypt EncryptAES1(ECryptoFlags_Decrypt | ECryptoFlags_UsePadding, KeyIV);
				DecryptedLen = EncryptAES1.f_Decrypt(Encrypted.f_GetArray(), EncryptedLen, Decrypted.f_GetArray(EncryptedLen + BlockSize));
				DMibExpectExceptionType(EncryptAES1.f_FinalizePaddedDecrypt(Decrypted.f_GetArray() + DecryptedLen, Decrypted.f_GetLen() - DecryptedLen), CExceptionCryptography);
			}

			{
				DMibTestPath("IncorrectSalt");
				CSecureByteVector IncorrectSalt = f_GetRandomBuffer(8, 4);
				auto KeyIV = CEncryptKeyIV::fs_GenerateKeyIV(Password, IncorrectSalt, CKeyDerivationSettings_PKCS5_Deprecated{});
				CIncrementalEncrypt EncryptAES2(ECryptoFlags_Decrypt | ECryptoFlags_UsePadding, KeyIV);
				DecryptedLen = EncryptAES2.f_Decrypt(Encrypted.f_GetArray(), EncryptedLen, Decrypted.f_GetArray());
				DMibExpectExceptionType(EncryptAES2.f_FinalizePaddedDecrypt(Decrypted.f_GetArray() + DecryptedLen, Decrypted.f_GetLen() - DecryptedLen), CExceptionCryptography);
			}

			{
				DMibTestPath("Incorrect Key");
				CEncryptKeyIV KeyIV = {WrongBuffer, CEncryptKeyIV::fs_GenerateKeyIV(Password, Salt, CKeyDerivationSettings_PKCS5_Deprecated{}).m_IV};
				CIncrementalEncrypt EncryptAES1(ECryptoFlags_Decrypt | ECryptoFlags_UsePadding, KeyIV);
				DecryptedLen = EncryptAES1.f_Decrypt(Encrypted.f_GetArray(), EncryptedLen, Decrypted.f_GetArray(EncryptedLen + BlockSize));
				DMibExpectExceptionType(EncryptAES1.f_FinalizePaddedDecrypt(Decrypted.f_GetArray() + DecryptedLen, Decrypted.f_GetLen() - DecryptedLen), CExceptionCryptography);
			}

			{
				// This test does not behave the same way as the incorrect key test, where the content of the final block did not decrypt correctly and finalization failed.
				// Nor is it an analogue to the the test with incorrect salt, which affects the key, which leads to incorrect decryption and finalization failure.
				//
				// After decryption the block is XORed with the IV. This means finalization will succeed, but the decrypted text will differ from the plain text.
				DMibTestPath("Incorrect IV");
				CEncryptKeyIV KeyIV = {CEncryptKeyIV::fs_GenerateKeyIV(Password, Salt, CKeyDerivationSettings_PKCS5_Deprecated{}).m_Key, WrongBuffer};
				CIncrementalEncrypt EncryptAES2(ECryptoFlags_Decrypt | ECryptoFlags_UsePadding, KeyIV);
				DecryptedLen = EncryptAES2.f_Decrypt(Encrypted.f_GetArray(), EncryptedLen, Decrypted.f_GetArray());
				DecryptedLen += EncryptAES2.f_FinalizePaddedDecrypt(Decrypted.f_GetArray() + DecryptedLen, Decrypted.f_GetLen() - DecryptedLen);
				Decrypted.f_SetLen(DecryptedLen);
				DMibExpect(Decrypted, !=, PlainText);
			}

			{
				DMibTestPath("Compare with OpenSSL enc");

				uint8 EncryptedByOpenSSL[] =
					{
						0x7e, 0x26, 0x44, 0x27, 0x23, 0x58, 0xfd, 0x32, 0xfa, 0x46, 0x80, 0xdc, 0xc0, 0x99, 0x45, 0x03,
						0x0d, 0x87, 0x20, 0xfc, 0x40, 0x5e, 0xb9, 0xd6, 0xed, 0xb9, 0x61, 0xc3, 0x98, 0x63, 0x58, 0xe8
					}
				;

				CByteVector EncryptedOpenSSL;
				EncryptedOpenSSL.f_SetLen(32);
				NMemory::fg_MemCopy(EncryptedOpenSSL.f_GetArray(), EncryptedByOpenSSL, 32);

				CByteVector ToEncrypt;
				ToEncrypt.f_SetLen(32);
				NMemory::fg_MemClear(ToEncrypt.f_GetArray(), ToEncrypt.f_GetLen());

				NStr::CStrSecure OpenSSLPassword("ABCDEFGH");
				auto KeyIV = CEncryptKeyIV::fs_GenerateKeyIV(OpenSSLPassword, {}, CKeyDerivationSettings_PKCS5_Deprecated{EDigestType_SHA256, 1}, ECryptoType_AES_256_CBC);
				CIncrementalEncrypt EncryptAES4(ECryptoFlags_Encrypt | ECryptoFlags_UsePadding, KeyIV);
				EncryptedLen = EncryptAES4.f_Encrypt(ToEncrypt.f_GetArray(), ToEncrypt.f_GetLen(), Encrypted.f_GetArray(ToEncrypt.f_GetLen() + BlockSize));
				EncryptedLen += EncryptAES4.f_FinalizePaddedEncrypt(Encrypted.f_GetArray() + EncryptedLen, Encrypted.f_GetLen() - EncryptedLen);
				// Remove the padding block from our encrypted data
				Encrypted.f_SetLen(EncryptedLen - BlockSize);
				DMibExpect(EncryptedOpenSSL, ==, Encrypted);

				// Cannot decrypt the OpenSSL block. It doesn't have correct padding.
			}
		};

		DMibTestSuite("Incremental Encrypt - No padding")
		{
			CStrSecure Password("MalterlibPasswordTest");
			// We use this buffer for both Key and IV
			CSecureByteVector Buffer
				{
					0x7e, 0x26, 0x44, 0x27, 0x23, 0x58, 0xfd, 0x32, 0xfa, 0x46, 0x80, 0xdc, 0xc0, 0x99, 0x45, 0x03,
					0x0d, 0x87, 0x20, 0xfc, 0x40, 0x5e, 0xb9, 0xd6, 0xed, 0xb9, 0x61, 0xc3, 0x98, 0x63, 0x58, 0xe8,
					0x7e, 0x26, 0x44, 0x22, 0x32, 0x58, 0xfd, 0x32, 0xfa, 0x46, 0x80, 0xdc, 0xc0, 0x99, 0x45, 0x03,
					0x0d, 0x87, 0x20, 0xfc, 0x40, 0x5e, 0xb9, 0xd6, 0xed, 0xb9, 0x61, 0xc3, 0x98, 0x63, 0x58, 0xe8
				}
			;

			CSecureByteVector Salt = f_GetRandomBuffer(8, 5);

			TCMap<ECryptoType, CStr> Ciphers =
				{
					{ECryptoType_AES_256_CBC, "ECryptoType_AES_256_CBC"}
					, {ECryptoType_AES_128_CBC, "ECryptoType_AES_128_CBC"}
					, {ECryptoType_AES_256_OFB, "ECryptoType_AES_256_OFB"}
					, {ECryptoType_AES_128_OFB, "ECryptoType_AES_128_OFB"}
					, {ECryptoType_DES_EDE3_CBC, "ECryptoType_DES_EDE3_CBC"}
					, {ECryptoType_AES_256_ECB, "ECryptoType_AES_256_ECB"}
					, {ECryptoType_AES_128_ECB, "ECryptoType_AES_128_ECB"}
				}
			;
			CByteVector PlainText;
			CByteVector Decrypted;
			CByteVector Encrypted;
			uint32 EncryptedLen;
			uint32 DecryptedLen;
			// Use multiple lengths: We do not use paddingin this test so stick to blocks that are multiples of the block size
			int const Lengths[] = { 32, 256, 65536 };

			for (auto Length : Lengths)
			{
				Encrypted.f_SetLen(Length);
				Decrypted.f_SetLen(Length);
				PlainText = f_GetRandomBuffer(Length, 9).f_ToInsecure();

				for (auto const &Cipher : Ciphers)
				{
					ECryptoType const CipherKey = Ciphers.fs_GetKey(Cipher);
					DMibTestPath(fg_Format("Cipher: {} Length: {}", Cipher, Length));

					CEncryptKeyIV KeyIV{Buffer, Buffer, CipherKey};
					CIncrementalEncrypt EncryptAES(ECryptoFlags_Encrypt, KeyIV);
					CIncrementalEncrypt DecryptAES(ECryptoFlags_Decrypt, KeyIV);
					EncryptedLen = EncryptAES.f_Encrypt(PlainText.f_GetArray(), PlainText.f_GetLen(), Encrypted.f_GetArray());
					DecryptedLen = DecryptAES.f_Decrypt(Encrypted.f_GetArray(), EncryptedLen, Decrypted.f_GetArray());
					DMibExpect(Decrypted, ==, PlainText);
					DMibExpect(Encrypted, !=, PlainText);
					DMibExpect(Decrypted, !=, Encrypted);
					DMibExpect(EncryptedLen, ==, Length);
					DMibExpect(DecryptedLen, ==, Length);
				}
			}
		};
	}
};

DMibTestRegister(CSymmetricCrypto_Tests, Malterlib::Crytpography);
