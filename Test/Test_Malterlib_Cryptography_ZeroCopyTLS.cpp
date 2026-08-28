// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Test/Exception>
#include <Mib/Cryptography/Certificate>
#include <Mib/Cryptography/BoringSSL>

using namespace NMib;
using namespace NMib::NStr;
using namespace NMib::NContainer;
using namespace NMib::NCryptography;

namespace
{
	struct CTLSPair
	{
		CTLSPair(uint16 _MinVersion, uint16 _MaxVersion)
		{
			CCertificateOptions Options;
			Options.m_CommonName = "localhost";
			Options.m_Hostnames = fg_CreateVector<CStr>("localhost");

			CByteVector CertData;
			CSecureByteVector KeyData;
			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, CertData, KeyData);

			X509 *pCertificate = NBoringSSL::fg_LoadCertificate(CertData);
			auto CleanupCertificate = g_OnScopeExit / [&]
				{
					X509_free(pCertificate);
				}
			;

			EVP_PKEY *pKey = NBoringSSL::fg_LoadPrivateKey(KeyData);
			auto CleanupKey = g_OnScopeExit / [&]
				{
					EVP_PKEY_free(pKey);
				}
			;

			m_pServerContext = SSL_CTX_new(TLS_method());
			m_pClientContext = SSL_CTX_new(TLS_method());
			DMibRequire(m_pServerContext && m_pClientContext);

			// Setup calls must execute even when contract checks are compiled out.
			for (SSL_CTX *pContext : {m_pServerContext, m_pClientContext})
			{
				if (!SSL_CTX_set_min_proto_version(pContext, _MinVersion) || !SSL_CTX_set_max_proto_version(pContext, _MaxVersion))
					DMibError("Could not set the TLS version bounds");
			}

			if (!SSL_CTX_use_certificate(m_pServerContext, pCertificate) || !SSL_CTX_use_PrivateKey(m_pServerContext, pKey))
				DMibError("Could not install the server certificate");
			SSL_CTX_set_verify(m_pClientContext, SSL_VERIFY_NONE, nullptr);

			m_pServer = SSL_new(m_pServerContext);
			m_pClient = SSL_new(m_pClientContext);
			DMibRequire(m_pServer && m_pClient);

			m_pServerRead = BIO_new(BIO_s_mem());
			m_pServerWrite = BIO_new(BIO_s_mem());
			m_pClientRead = BIO_new(BIO_s_mem());
			m_pClientWrite = BIO_new(BIO_s_mem());
			DMibRequire(m_pServerRead && m_pServerWrite && m_pClientRead && m_pClientWrite);

			SSL_set_bio(m_pServer, m_pServerRead, m_pServerWrite);
			SSL_set_bio(m_pClient, m_pClientRead, m_pClientWrite);

			SSL_set_accept_state(m_pServer);
			SSL_set_connect_state(m_pClient);
		}

		~CTLSPair()
		{
			SSL_free(m_pServer);
			SSL_free(m_pClient);
			SSL_CTX_free(m_pServerContext);
			SSL_CTX_free(m_pClientContext);
		}

		CTLSPair(CTLSPair const &) = delete;
		CTLSPair &operator = (CTLSPair const &) = delete;

		static void fs_Pump(BIO *_pFrom, BIO *_pTo)
		{
			uint8 Buffer[4096];
			int Read;

			while ((Read = BIO_read(_pFrom, Buffer, sizeof(Buffer))) > 0)
				BIO_write(_pTo, Buffer, Read);
		}

		bool f_Handshake()
		{
			for (aint i = 0; i < 32; ++i)
			{
				SSL_do_handshake(m_pClient);
				fs_Pump(m_pClientWrite, m_pServerRead);
				SSL_do_handshake(m_pServer);
				fs_Pump(m_pServerWrite, m_pClientRead);

				if (SSL_is_init_finished(m_pClient) && SSL_is_init_finished(m_pServer))
					return true;
			}

			return false;
		}

		// TLS 1.3 post-handshake tickets must drain before tests expecting only application records.
		void f_SettlePostHandshake()
		{
			// Pending tickets leave on the next write, so both peers must write once.
			uint8 Buffer[4096];
			uint8 const Probe = 0;

			for (aint i = 0; i < 2; ++i)
			{
				SSL_write(m_pServer, &Probe, 1);
				fs_Pump(m_pServerWrite, m_pClientRead);
				while (SSL_read(m_pClient, Buffer, sizeof(Buffer)) > 0)
					;

				SSL_write(m_pClient, &Probe, 1);
				fs_Pump(m_pClientWrite, m_pServerRead);
				while (SSL_read(m_pServer, Buffer, sizeof(Buffer)) > 0)
					;
			}

			fs_Drain(m_pServerWrite);
			fs_Drain(m_pClientWrite);
		}

		static CByteVector fs_Drain(BIO *_pFrom)
		{
			CByteVector Data;
			uint8 Buffer[4096];
			int Read;

			while ((Read = BIO_read(_pFrom, Buffer, sizeof(Buffer))) > 0)
				Data.f_Insert(Buffer, umint(Read));

			return Data;
		}

		SSL_CTX *m_pServerContext = nullptr;
		SSL_CTX *m_pClientContext = nullptr;
		SSL *m_pServer = nullptr;
		SSL *m_pClient = nullptr;
		BIO *m_pServerRead = nullptr;
		BIO *m_pServerWrite = nullptr;
		BIO *m_pClientRead = nullptr;
		BIO *m_pClientWrite = nullptr;
	};

	// Use uneven fragments to exercise boundaries both on and off the AEAD block size.
	TCVector<CRYPTO_IVEC> fg_SplitInput(uint8 const *_pData, umint _nBytes, umint _nFragments)
	{
		TCVector<CRYPTO_IVEC> Fragments;
		if (!_nFragments)
			return Fragments;

		umint Offset = 0;
		for (umint i = 0; i < _nFragments; ++i)
		{
			umint Remaining = _nBytes - Offset;
			umint Take = (i + 1 == _nFragments) ? Remaining : fg_Min(Remaining, (_nBytes / _nFragments) + (i % 3));
			Fragments.f_InsertLast(CRYPTO_IVEC{_pData + Offset, Take});
			Offset += Take;
		}

		return Fragments;
	}

	TCVector<CRYPTO_IOVEC> fg_SplitOutput(uint8 *_pData, umint _nBytes, umint _nFragments)
	{
		TCVector<CRYPTO_IOVEC> Fragments;
		if (!_nFragments)
			return Fragments;

		umint Offset = 0;
		for (umint i = 0; i < _nFragments; ++i)
		{
			umint Remaining = _nBytes - Offset;
			umint Take = (i + 1 == _nFragments) ? Remaining : fg_Min(Remaining, (_nBytes / _nFragments) + (i % 3));
			Fragments.f_InsertLast(CRYPTO_IOVEC{_pData + Offset, nullptr, Take});
			Offset += Take;
		}

		return Fragments;
	}

	CByteVector fg_MakePayload(umint _nBytes)
	{
		CByteVector Payload;
		Payload.f_SetLen(_nBytes);
		for (umint i = 0; i < _nBytes; ++i)
			Payload[i] = uint8((i * 31 + (i >> 8) * 7) & 0xff);

		return Payload;
	}

	class CZeroCopyTLS_Tests : public NMib::NTest::CTest
	{
	public:
		void fp_TestSealGather(CTLSPair &_Pair, CByteVector const &_Payload, umint _nFragments)
		{
			auto Fragments = fg_SplitInput(_Payload.f_GetArray(), _Payload.f_GetLen(), _nFragments);

			CByteVector Ciphertext;
			Ciphertext.f_SetLen(_Payload.f_GetLen() + 4096);

			umint Consumed = 0;
			CByteVector Plaintext;

			// A short record is a legitimate outcome when the fragment budget
			// runs out, so seal in a loop until the payload is taken.
			while (Consumed < _Payload.f_GetLen())
			{
				auto Remaining = fg_SplitInput
					(
						_Payload.f_GetArray() + Consumed
						, _Payload.f_GetLen() - Consumed
						, fg_Min(_nFragments, _Payload.f_GetLen() - Consumed)
					)
				;

				size_t Written = 0;
				size_t RoundConsumed = 0;
				auto Result = SSL_seal_app_datav
					(
						_Pair.m_pClient
						, Ciphertext.f_GetArray()
						, &Written
						, Ciphertext.f_GetLen()
						, Remaining.f_GetArray()
						, Remaining.f_GetLen()
						, &RoundConsumed
					)
				;

				DMibExpect(int(Result), ==, int(ssl_seal_v_success));
				if (Result != ssl_seal_v_success)
					return;

				DMibExpect(RoundConsumed, >, umint(0));
				if (!RoundConsumed)
					return;

				BIO_write(_Pair.m_pServerRead, Ciphertext.f_GetArray(), int(Written));
				Consumed += RoundConsumed;

				uint8 Buffer[8192];
				int Read;
				while ((Read = SSL_read(_Pair.m_pServer, Buffer, sizeof(Buffer))) > 0)
					Plaintext.f_Insert(Buffer, umint(Read));
			}

			DMibExpect(Plaintext.f_GetLen(), ==, _Payload.f_GetLen());
			DMibExpect(Plaintext, ==, _Payload);
		}

		void fp_TestOpenScatter(CTLSPair &_Pair, CByteVector const &_Payload, umint _nInFragments, umint _nOutFragments)
		{
			DMibExpect(SSL_write(_Pair.m_pServer, _Payload.f_GetArray(), int(_Payload.f_GetLen())), ==, int(_Payload.f_GetLen()));

			CByteVector Ciphertext = CTLSPair::fs_Drain(_Pair.m_pServerWrite);
			DMibExpect(Ciphertext.f_GetLen(), >, umint(0));

			// The output has to hold whole record bodies, not just plaintext.
			CByteVector Destination;
			Destination.f_SetLen(Ciphertext.f_GetLen());

			auto InFragments = fg_SplitInput(Ciphertext.f_GetArray(), Ciphertext.f_GetLen(), _nInFragments);
			auto OutFragments = fg_SplitOutput(Destination.f_GetArray(), Destination.f_GetLen(), _nOutFragments);

			size_t Produced = 0;
			size_t Consumed = 0;
			auto Result = SSL_open_app_datav
				(
					_Pair.m_pClient
					, OutFragments.f_GetArray()
					, OutFragments.f_GetLen()
					, &Produced
					, &Consumed
					, InFragments.f_GetArray()
					, InFragments.f_GetLen()
				)
			;

			DMibExpect(int(Result), ==, int(ssl_open_v_success));
			DMibExpect(Consumed, ==, Ciphertext.f_GetLen());
			DMibExpect(Produced, ==, _Payload.f_GetLen());

			if (Produced != _Payload.f_GetLen())
				return;

			Destination.f_SetLen(Produced);
			DMibExpect(Destination, ==, _Payload);
		}

		void fp_TestVersion(CStr const &_Name, uint16 _Version)
		{
			DMibTestCategory(_Name)
			{
				DMibTestSuite("Seal gather")
				{
					for (umint nFragments : {umint(1), umint(2), umint(3), umint(15), umint(20)})
					{
						{
							DMibTestPath("{}"_f << nFragments);
							CTLSPair Pair(_Version, _Version);
							DMibExpect(Pair.f_Handshake(), ==, true);

							fp_TestSealGather(Pair, fg_MakePayload(4096), nFragments);
						}
					}

					{
						DMibTestPath("Multi record");
						CTLSPair Pair(_Version, _Version);
						DMibExpect(Pair.f_Handshake(), ==, true);

						fp_TestSealGather(Pair, fg_MakePayload(40000), 5);
					}

					{
						DMibTestPath("Empty payload");
						CTLSPair Pair(_Version, _Version);
						DMibExpect(Pair.f_Handshake(), ==, true);

						CByteVector Empty;
						CRYPTO_IVEC Fragment{nullptr, 0};
						CByteVector Ciphertext;
						Ciphertext.f_SetLen(4096);

						size_t Written = 0;
						size_t Consumed = 0;
						DMibExpect
							(
								int
									(
										SSL_seal_app_datav
											(
												Pair.m_pClient
												, Ciphertext.f_GetArray()
												, &Written
												, Ciphertext.f_GetLen()
												, &Fragment
												, 1
												, &Consumed
											)
									)
								, ==
								, int(ssl_seal_v_success)
							)
						;
						DMibExpect(Consumed, ==, umint(0));
					}
				};

				DMibTestSuite("Open scatter")
				{
					for (umint nIn : {umint(1), umint(2), umint(7)})
					{
						for (umint nOut : {umint(1), umint(3)})
						{
							{
								DMibTestPath("{} in {} out"_f << nIn << nOut);
								CTLSPair Pair(_Version, _Version);
								DMibExpect(Pair.f_Handshake(), ==, true);

								fp_TestOpenScatter(Pair, fg_MakePayload(4096), nIn, nOut);
							}
						}
					}

					{
						DMibTestPath("Straddling records");
						CTLSPair Pair(_Version, _Version);
						DMibExpect(Pair.f_Handshake(), ==, true);

						fp_TestOpenScatter(Pair, fg_MakePayload(40000), 2, 2);
					}
				};

				DMibTestSuite("Post handshake")
				{
					// Midstream handshake messages must be processed rather than exposed as application data.
					if (_Version >= TLS1_3_VERSION)
					{
						DMibTestPath("KeyUpdate");
						CTLSPair Pair(_Version, _Version);
						DMibExpect(Pair.f_Handshake(), ==, true);

						Pair.f_SettlePostHandshake();

						DMibExpect(SSL_key_update(Pair.m_pServer, SSL_KEY_UPDATE_REQUESTED), ==, 1);

						// The KeyUpdate goes out ahead of the application data,
						// so the client sees both in one run of records.
						CByteVector Payload = fg_MakePayload(2048);
						DMibExpect(SSL_write(Pair.m_pServer, Payload.f_GetArray(), int(Payload.f_GetLen())), ==, int(Payload.f_GetLen()));

						CByteVector Ciphertext = CTLSPair::fs_Drain(Pair.m_pServerWrite);
						DMibExpect(Ciphertext.f_GetLen(), >, Payload.f_GetLen());

						CByteVector Destination;
						Destination.f_SetLen(Ciphertext.f_GetLen());

						CRYPTO_IVEC InFragment{Ciphertext.f_GetArray(), Ciphertext.f_GetLen()};
						CRYPTO_IOVEC OutFragment{Destination.f_GetArray(), nullptr, Destination.f_GetLen()};

						size_t Produced = 0;
						size_t Consumed = 0;
						auto Result = SSL_open_app_datav(Pair.m_pClient, &OutFragment, 1, &Produced, &Consumed, &InFragment, 1);

						DMibExpect(int(Result), ==, int(ssl_open_v_success));
						DMibExpect(Consumed, ==, Ciphertext.f_GetLen());
						DMibExpect(Produced, ==, Payload.f_GetLen());

						if (Produced == Payload.f_GetLen())
						{
							Destination.f_SetLen(Produced);
							DMibExpect(Destination, ==, Payload);
						}

						// The KeyUpdate reply is queued as pending handshake
						// data and has to go out ahead of the next records.
						CByteVector Reply;
						Reply.f_SetLen(8192);
						CByteVector ReplyPayload = fg_MakePayload(64);
						CRYPTO_IVEC ReplyFragment{ReplyPayload.f_GetArray(), ReplyPayload.f_GetLen()};

						size_t Written = 0;
						size_t ReplyConsumed = 0;
						DMibExpect(int(SSL_seal_app_datav(Pair.m_pClient, Reply.f_GetArray(), &Written, Reply.f_GetLen(), &ReplyFragment, 1, &ReplyConsumed)), ==, int(ssl_seal_v_success));
						DMibExpect(ReplyConsumed, ==, ReplyPayload.f_GetLen());

						DMibExpect(Written, >, ReplyPayload.f_GetLen() + umint(32));

						BIO_write(Pair.m_pServerRead, Reply.f_GetArray(), int(Written));
						uint8 Buffer[256];
						int Read = SSL_read(Pair.m_pServer, Buffer, sizeof(Buffer));
						DMibExpect(Read, ==, int(ReplyPayload.f_GetLen()));
					}
				};

				DMibTestSuite("Preconditions")
				{
					{
						DMibTestPath("Before handshake");
						CTLSPair Pair(_Version, _Version);

						CByteVector Payload = fg_MakePayload(16);
						CByteVector Ciphertext;
						Ciphertext.f_SetLen(4096);
						CRYPTO_IVEC Fragment{Payload.f_GetArray(), Payload.f_GetLen()};

						size_t Written = 0;
						size_t Consumed = 0;
						DMibExpect(int(SSL_seal_app_datav(Pair.m_pClient, Ciphertext.f_GetArray(), &Written, Ciphertext.f_GetLen(), &Fragment, 1, &Consumed)), ==, int(ssl_seal_v_refused));

						CByteVector Destination;
						Destination.f_SetLen(4096);
						CRYPTO_IOVEC OutFragment{Destination.f_GetArray(), nullptr, Destination.f_GetLen()};
						size_t Produced = 0;
						size_t InConsumed = 0;
						DMibExpect(int(SSL_open_app_datav(Pair.m_pClient, &OutFragment, 1, &Produced, &InConsumed, &Fragment, 1)), ==, int(ssl_open_v_refused));
					}

					{
						DMibTestPath("Record longer than one can be");
						CTLSPair Pair(_Version, _Version);
						DMibExpect(Pair.f_Handshake(), ==, true);
						Pair.f_SettlePostHandshake();

						// Reject oversized advertised bodies before waiting, or a bounded receive buffer could stall forever.
						uint8 Header[SSL3_RT_HEADER_LENGTH] = {SSL3_RT_APPLICATION_DATA, 0x03, 0x03, 0xFF, 0xFF};

						CByteVector Destination;
						Destination.f_SetLen(4096);
						CRYPTO_IVEC InFragment{Header, sizeof(Header)};
						CRYPTO_IOVEC OutFragment{Destination.f_GetArray(), nullptr, Destination.f_GetLen()};

						size_t Produced = 0;
						size_t Consumed = 0;
						DMibExpect(int(SSL_open_app_datav(Pair.m_pClient, &OutFragment, 1, &Produced, &Consumed, &InFragment, 1)), ==, int(ssl_open_v_error));
					}

					{
						DMibTestPath("Records opened before a failure are reported");
						CTLSPair Pair(_Version, _Version);
						DMibExpect(Pair.f_Handshake(), ==, true);
						Pair.f_SettlePostHandshake();

						// Opening the first record spends its sequence number; a later failure must still report its plaintext.
						CByteVector First = fg_MakePayload(64);
						DMibExpect(SSL_write(Pair.m_pServer, First.f_GetArray(), int(First.f_GetLen())), ==, int(First.f_GetLen()));
						CByteVector Ciphertext = CTLSPair::fs_Drain(Pair.m_pServerWrite);
						umint FirstLen = Ciphertext.f_GetLen();

						CByteVector Second = fg_MakePayload(64);
						DMibExpect(SSL_write(Pair.m_pServer, Second.f_GetArray(), int(Second.f_GetLen())), ==, int(Second.f_GetLen()));
						CByteVector SecondData = CTLSPair::fs_Drain(Pair.m_pServerWrite);
						DMibExpect(SecondData.f_GetLen(), >, umint(SSL3_RT_HEADER_LENGTH));

						// Past the header, so the length still parses and the body fails its tag
						SecondData[SSL3_RT_HEADER_LENGTH] = uint8(SecondData[SSL3_RT_HEADER_LENGTH] ^ 0xFF);
						Ciphertext.f_Insert(SecondData.f_GetArray(), SecondData.f_GetLen());

						CByteVector Destination;
						Destination.f_SetLen(8192);
						CRYPTO_IVEC InFragment{Ciphertext.f_GetArray(), Ciphertext.f_GetLen()};
						CRYPTO_IOVEC OutFragment{Destination.f_GetArray(), nullptr, Destination.f_GetLen()};

						size_t Produced = 0;
						size_t Consumed = 0;
						DMibExpect(int(SSL_open_app_datav(Pair.m_pClient, &OutFragment, 1, &Produced, &Consumed, &InFragment, 1)), ==, int(ssl_open_v_error));
						DMibExpect(Consumed, ==, FirstLen);
						DMibExpect(Produced, ==, First.f_GetLen());

						CByteVector Opened;
						Opened.f_Insert(Destination.f_GetArray(), Produced);
						DMibExpect(Opened, ==, First);
					}

					{
						DMibTestPath("Sealing after the write side is shut");
						CTLSPair Pair(_Version, _Version);
						DMibExpect(Pair.f_Handshake(), ==, true);
						Pair.f_SettlePostHandshake();

						SSL_shutdown(Pair.m_pClient);
						CTLSPair::fs_Drain(Pair.m_pClientWrite);

						CByteVector Payload = fg_MakePayload(16);
						CByteVector Ciphertext;
						Ciphertext.f_SetLen(4096);
						CRYPTO_IVEC Fragment{Payload.f_GetArray(), Payload.f_GetLen()};

						size_t Written = 0;
						size_t Consumed = 0;
						DMibExpect(int(SSL_seal_app_datav(Pair.m_pClient, Ciphertext.f_GetArray(), &Written, Ciphertext.f_GetLen(), &Fragment, 1, &Consumed)), ==, int(ssl_seal_v_refused));
						DMibExpect(Written, ==, umint(0));
						DMibExpect(Consumed, ==, umint(0));
					}

					{
						DMibTestPath("Output sized to the plaintext");
						CTLSPair Pair(_Version, _Version);
						DMibExpect(Pair.f_Handshake(), ==, true);
						Pair.f_SettlePostHandshake();

						// Allow plaintext-sized output even when record framing would not fit.
						CByteVector Payload = fg_MakePayload(20000);
						DMibExpect(SSL_write(Pair.m_pServer, Payload.f_GetArray(), int(Payload.f_GetLen())), ==, int(Payload.f_GetLen()));
						CByteVector Ciphertext = CTLSPair::fs_Drain(Pair.m_pServerWrite);

						CByteVector Destination;
						Destination.f_SetLen(Payload.f_GetLen());

						CRYPTO_IVEC InFragment{Ciphertext.f_GetArray(), Ciphertext.f_GetLen()};
						CRYPTO_IOVEC OutFragment{Destination.f_GetArray(), nullptr, Destination.f_GetLen()};

						size_t Produced = 0;
						size_t Consumed = 0;
						DMibExpect(int(SSL_open_app_datav(Pair.m_pClient, &OutFragment, 1, &Produced, &Consumed, &InFragment, 1)), ==, int(ssl_open_v_success));

						// TLS 1.3 writes an inner content type beyond the plaintext, so an exact payload-sized destination can stop one record short.
						DMibExpect(Produced, >=, umint(SSL3_RT_MAX_PLAIN_LENGTH));
						DMibExpect(Consumed, >, umint(0));

						CByteVector Prefix;
						Prefix.f_Insert(Payload.f_GetArray(), Produced);
						Destination.f_SetLen(Produced);
						DMibExpect(Destination, ==, Prefix);
					}

					{
						DMibTestPath("Opened in place");
						CTLSPair Pair(_Version, _Version);
						DMibExpect(Pair.f_Handshake(), ==, true);
						Pair.f_SettlePostHandshake();

						// Two records, so the second's plaintext lands below its own ciphertext
						CByteVector Payload = fg_MakePayload(20000);
						DMibExpect(SSL_write(Pair.m_pServer, Payload.f_GetArray(), int(Payload.f_GetLen())), ==, int(Payload.f_GetLen()));
						CByteVector Buffer = CTLSPair::fs_Drain(Pair.m_pServerWrite);

						CRYPTO_IVEC InFragment{Buffer.f_GetArray(), Buffer.f_GetLen()};
						CRYPTO_IOVEC OutFragment{Buffer.f_GetArray() + SSL3_RT_HEADER_LENGTH, nullptr, Buffer.f_GetLen() - SSL3_RT_HEADER_LENGTH};

						size_t Produced = 0;
						size_t Consumed = 0;
						DMibExpect(int(SSL_open_app_datav(Pair.m_pClient, &OutFragment, 1, &Produced, &Consumed, &InFragment, 1)), ==, int(ssl_open_v_success));
						DMibExpect(Consumed, ==, Buffer.f_GetLen());
						DMibExpect(Produced, ==, Payload.f_GetLen());

						CByteVector Opened;
						Opened.f_Insert(Buffer.f_GetArray() + SSL3_RT_HEADER_LENGTH, Produced);
						DMibExpect(Opened, ==, Payload);
					}

					{
						DMibTestPath("Overlap short of the input end is refused");
						CTLSPair Pair(_Version, _Version);
						DMibExpect(Pair.f_Handshake(), ==, true);
						Pair.f_SettlePostHandshake();

						// Opening in place writes where the ciphertext lies, which a short output would not cover
						CByteVector Payload = fg_MakePayload(64);
						DMibExpect(SSL_write(Pair.m_pServer, Payload.f_GetArray(), int(Payload.f_GetLen())), ==, int(Payload.f_GetLen()));
						CByteVector Buffer = CTLSPair::fs_Drain(Pair.m_pServerWrite);
						CByteVector Untouched = Buffer;

						CRYPTO_IVEC InFragment{Buffer.f_GetArray(), Buffer.f_GetLen()};
						CRYPTO_IOVEC OutFragment{Buffer.f_GetArray(), nullptr, Payload.f_GetLen() + 1};

						size_t Produced = 0;
						size_t Consumed = 0;
						DMibExpect(int(SSL_open_app_datav(Pair.m_pClient, &OutFragment, 1, &Produced, &Consumed, &InFragment, 1)), ==, int(ssl_open_v_refused));
						DMibExpect(Consumed, ==, umint(0));
						DMibExpect(Buffer, ==, Untouched);
					}

					{
						DMibTestPath("Shifted overlap is refused");
						CTLSPair Pair(_Version, _Version);
						DMibExpect(Pair.f_Handshake(), ==, true);
						Pair.f_SettlePostHandshake();

						CByteVector Payload = fg_MakePayload(20000);
						DMibExpect(SSL_write(Pair.m_pServer, Payload.f_GetArray(), int(Payload.f_GetLen())), ==, int(Payload.f_GetLen()));
						CByteVector Buffer = CTLSPair::fs_Drain(Pair.m_pServerWrite);

						CRYPTO_IVEC InFragment{Buffer.f_GetArray(), Buffer.f_GetLen()};
						CRYPTO_IOVEC OutFragment{Buffer.f_GetArray() + SSL3_RT_HEADER_LENGTH + 1, nullptr, Buffer.f_GetLen() - SSL3_RT_HEADER_LENGTH - 1};

						size_t Produced = 0;
						size_t Consumed = 0;
						DMibExpect(int(SSL_open_app_datav(Pair.m_pClient, &OutFragment, 1, &Produced, &Consumed, &InFragment, 1)), ==, int(ssl_open_v_refused));
						DMibExpect(Consumed, ==, umint(0));

						// Refusal leaves the connection usable
						CByteVector Destination;
						Destination.f_SetLen(Buffer.f_GetLen());
						CRYPTO_IOVEC Separate{Destination.f_GetArray(), nullptr, Destination.f_GetLen()};
						DMibExpect(int(SSL_open_app_datav(Pair.m_pClient, &Separate, 1, &Produced, &Consumed, &InFragment, 1)), ==, int(ssl_open_v_success));
						DMibExpect(Produced, ==, Payload.f_GetLen());
					}

					{
						DMibTestPath("Output too small");
						CTLSPair Pair(_Version, _Version);
						DMibExpect(Pair.f_Handshake(), ==, true);
						Pair.f_SettlePostHandshake();

						CByteVector Payload = fg_MakePayload(1024);
						DMibExpect(SSL_write(Pair.m_pServer, Payload.f_GetArray(), int(Payload.f_GetLen())), ==, int(Payload.f_GetLen()));
						CByteVector Ciphertext = CTLSPair::fs_Drain(Pair.m_pServerWrite);

						CByteVector Destination;
						Destination.f_SetLen(8);
						CRYPTO_IVEC InFragment{Ciphertext.f_GetArray(), Ciphertext.f_GetLen()};
						CRYPTO_IOVEC OutFragment{Destination.f_GetArray(), nullptr, Destination.f_GetLen()};

						size_t Produced = 0;
						size_t Consumed = 0;
						DMibExpect(int(SSL_open_app_datav(Pair.m_pClient, &OutFragment, 1, &Produced, &Consumed, &InFragment, 1)), ==, int(ssl_open_v_success));
						DMibExpect(Produced, ==, umint(0));
						DMibExpect(Consumed, ==, umint(0));
					}

					{
						DMibTestPath("Incomplete record");
						CTLSPair Pair(_Version, _Version);
						DMibExpect(Pair.f_Handshake(), ==, true);
						Pair.f_SettlePostHandshake();

						CByteVector Payload = fg_MakePayload(1024);
						DMibExpect(SSL_write(Pair.m_pServer, Payload.f_GetArray(), int(Payload.f_GetLen())), ==, int(Payload.f_GetLen()));
						CByteVector Ciphertext = CTLSPair::fs_Drain(Pair.m_pServerWrite);

						CByteVector Destination;
						Destination.f_SetLen(Ciphertext.f_GetLen());

						CRYPTO_IVEC InFragment{Ciphertext.f_GetArray(), Ciphertext.f_GetLen() - 1};
						CRYPTO_IOVEC OutFragment{Destination.f_GetArray(), nullptr, Destination.f_GetLen()};

						size_t Produced = 0;
						size_t Consumed = 0;
						DMibExpect(int(SSL_open_app_datav(Pair.m_pClient, &OutFragment, 1, &Produced, &Consumed, &InFragment, 1)), ==, int(ssl_open_v_success));
						DMibExpect(Produced, ==, umint(0));
						DMibExpect(Consumed, ==, umint(0));

						CRYPTO_IVEC Split[2] =
						{
							{Ciphertext.f_GetArray(), Ciphertext.f_GetLen() - 1}
							, {Ciphertext.f_GetArray() + Ciphertext.f_GetLen() - 1, 1}
						};

						DMibExpect(int(SSL_open_app_datav(Pair.m_pClient, &OutFragment, 1, &Produced, &Consumed, Split, 2)), ==, int(ssl_open_v_success));
						DMibExpect(Consumed, ==, Ciphertext.f_GetLen());
						DMibExpect(Produced, ==, Payload.f_GetLen());

						if (Produced == Payload.f_GetLen())
						{
							Destination.f_SetLen(Produced);
							DMibExpect(Destination, ==, Payload);
						}
					}
				};

				DMibTestSuite("Round trip")
				{
					CTLSPair Pair(_Version, _Version);
					{
						DMibTestPath("Handshake");
						DMibExpect(Pair.f_Handshake(), ==, true);
					}

					{
						DMibTestPath("Seal first");
						fp_TestSealGather(Pair, fg_MakePayload(9000), 4);
					}
					{
						DMibTestPath("Open second");
						fp_TestOpenScatter(Pair, fg_MakePayload(9000), 3, 2);
					}
					{
						DMibTestPath("Seal single byte");
						fp_TestSealGather(Pair, fg_MakePayload(1), 1);
					}
				};
			};
		}

		void f_DoTests()
		{
			fp_TestVersion("TLS 1.2", TLS1_2_VERSION);
			fp_TestVersion("TLS 1.3", TLS1_3_VERSION);
		}
	};
}

DMibTestRegister(CZeroCopyTLS_Tests, Malterlib::Cryptography);
