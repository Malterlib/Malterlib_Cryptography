// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Network/SSL>
#include <Mib/Test/Exception>
#include <Mib/Cryptography/Certificate>
#include <Mib/Cryptography/SymmetricCrypto>
#include <Mib/Cryptography/BoringSSL>

using namespace NMib;
using namespace NMib::NStr;
using namespace NMib::NContainer;
using namespace NMib::NCryptography;

class CPublicCrypto_Tests : public NMib::NTest::CTest
{
public:
	void f_DoTests()
	{
		DMibTestSuite("Public Key Signing and Verifying")
		{
			static const char *Text = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";
			CSecureByteVector Message;
			NMemory::fg_MemCopy(Message.f_GetArray(fg_StrLen(Text)), Text, fg_StrLen(Text));
			CSecureByteVector Truncated(Message);
			Truncated.f_SetLen(Truncated.f_GetLen() - 1);

			// Apparently we cannot create EPublicKeyType::mc_EC_X25519 keys
			for (EPublicKeyType KeyType = EPublicKeyType::mc_RSA; KeyType <= EPublicKeyType::mc_EC_secp521r1; KeyType = EPublicKeyType(uint32(KeyType) + 1))
			{
				DMibTestPath("KeySetting {}"_f << KeyType);

				CPublicKeySetting KeySettings;
				switch (KeyType)
				{
				case EPublicKeyType::mc_RSA:          KeySettings = CPublicKeySettings_RSA{};          break;
				case EPublicKeyType::mc_EC_secp256r1: KeySettings = CPublicKeySettings_EC_secp256r1{}; break;
				case EPublicKeyType::mc_EC_secp384r1: KeySettings = CPublicKeySettings_EC_secp384r1{}; break;
				case EPublicKeyType::mc_EC_secp521r1: KeySettings = CPublicKeySettings_EC_secp521r1{}; break;
				case EPublicKeyType::mc_EC_X25519:    KeySettings = CPublicKeySettings_EC_X25519{};    break;
				}

				NContainer::CSecureByteVector PrivateKey;
				NContainer::CSecureByteVector PublicKey;
				CPublicCrypto::fs_GenerateKeys(PrivateKey, PublicKey, KeySettings);
				NContainer::CSecureByteVector Signature = CPublicCrypto::fs_SignMessage(Message, PrivateKey);
				DMibExpectTrue(CPublicCrypto::fs_VerifySignature(Message, PublicKey, Signature));

				// Different message - should not be verified
				DMibExpectFalse(CPublicCrypto::fs_VerifySignature(Truncated, PublicKey, Signature));

				// Tamper with signature - outcome differs depending on the key type. RSA fails verification, but EC throws and exception about a broken signature
				Signature[0] ^= 0x1;
				DMibExpectFalse(CPublicCrypto::fs_VerifySignature(Message, PublicKey, Signature));
			}
			{
				NContainer::CSecureByteVector PrivateKey;
				NContainer::CSecureByteVector PublicKey;
				CPublicCrypto::fs_GenerateKeys(PrivateKey, PublicKey);
				EDigestType DigestsTypes[] = { EDigestType_SHA512, EDigestType_SHA384, EDigestType_SHA256 };
				for (auto DigestType : DigestsTypes)
				{
					DMibTestPath("DigestType {}"_f << DigestType);
					NContainer::CSecureByteVector Signature = CPublicCrypto::fs_SignMessage(Message, PrivateKey, DigestType);
					DMibExpectTrue(CPublicCrypto::fs_VerifySignature(Message, PublicKey, Signature, DigestType));
				}
			}
		};
		DMibTestSuite("Raw EC Signatures")
		{
			// R and S are fixed width in a raw signature (JWS ES256 and friends). A component with leading zero bytes, 1 in 256 for P-256 and about
			// every other for P-521, has to be padded with zeros. Each signature is converted to DER and verified.
			for (EPublicKeyType KeyType = EPublicKeyType::mc_EC_secp256r1; KeyType <= EPublicKeyType::mc_EC_secp521r1; KeyType = EPublicKeyType(uint32(KeyType) + 1))
			{
				DMibTestPath("KeySetting {}"_f << KeyType);

				CPublicKeySetting KeySettings;
				umint ComponentSize = 0;
				switch (KeyType)
				{
				case EPublicKeyType::mc_EC_secp256r1: KeySettings = CPublicKeySettings_EC_secp256r1{}; ComponentSize = 32; break;
				case EPublicKeyType::mc_EC_secp384r1: KeySettings = CPublicKeySettings_EC_secp384r1{}; ComponentSize = 48; break;
				case EPublicKeyType::mc_EC_secp521r1: KeySettings = CPublicKeySettings_EC_secp521r1{}; ComponentSize = 66; break;
				default: break;
				}

				NContainer::CSecureByteVector PrivateKey;
				NContainer::CSecureByteVector PublicKey;
				CPublicCrypto::fs_GenerateKeys(PrivateKey, PublicKey, KeySettings);

				umint nFailed = 0;
				umint nWrongLength = 0;
				for (umint i = 0; i < 1000; ++i)
				{
					CStr Text = "Message {}"_f << i;
					CSecureByteVector Message;
					NMemory::fg_MemCopy(Message.f_GetArray(Text.f_GetLen()), Text.f_GetStr(), Text.f_GetLen());

					CSecureByteVector RawSignature = CPublicCrypto::fs_SignMessageRawSignature(Message, PrivateKey);
					if (RawSignature.f_GetLen() != ComponentSize * 2)
					{
						++nWrongLength;
						continue;
					}

					ECDSA_SIG *pSignature = ECDSA_SIG_new();
					ECDSA_SIG_set0
						(
							pSignature
							, BN_bin2bn(RawSignature.f_GetArray(), ComponentSize, nullptr)
							, BN_bin2bn(RawSignature.f_GetArray() + ComponentSize, ComponentSize, nullptr)
						)
					;
					uint8 *pDer = nullptr;
					size_t DerLength = 0;
					ECDSA_SIG_to_bytes(&pDer, &DerLength, pSignature);
					CSecureByteVector DerSignature;
					NMemory::fg_MemCopy(DerSignature.f_GetArray(DerLength), pDer, DerLength);
					OPENSSL_free(pDer);
					ECDSA_SIG_free(pSignature);

					if (!CPublicCrypto::fs_VerifySignature(Message, PublicKey, DerSignature))
						++nFailed;
				}

				DMibExpect(nWrongLength, ==, 0);
				DMibExpect(nFailed, ==, 0);
			}
		};
	}
};

DMibTestRegister(CPublicCrypto_Tests, Malterlib::Cryptography);
