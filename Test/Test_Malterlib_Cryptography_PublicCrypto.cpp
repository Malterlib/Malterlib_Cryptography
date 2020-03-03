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

			// Apparently we cannot create EPublicKeyType_EC_X25519 keys
			for (aint KeyType = EPublicKeyType_RSA; KeyType <= EPublicKeyType_EC_secp521r1; ++KeyType)
			{
				DMibTestPath("KeySetting {}"_f << KeyType);

				CPublicKeySetting KeySettings;
				switch (KeyType)
				{
				case EPublicKeyType_RSA:          KeySettings = CPublicKeySettings_RSA{};          break;
				case EPublicKeyType_EC_secp256r1: KeySettings = CPublicKeySettings_EC_secp256r1{}; break;
				case EPublicKeyType_EC_secp384r1: KeySettings = CPublicKeySettings_EC_secp384r1{}; break;
				case EPublicKeyType_EC_secp521r1: KeySettings = CPublicKeySettings_EC_secp521r1{}; break;
				case EPublicKeyType_EC_X25519:    KeySettings = CPublicKeySettings_EC_X25519{};    break;
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
	}
};

DMibTestRegister(CPublicCrypto_Tests, Malterlib::Crytpography);
