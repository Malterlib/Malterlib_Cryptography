// Copyright © 2018 Nonna Holding AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

#include <Mib/Core/Core>
#include <Mib/String/String>

namespace NMib::NCryptography
{
	template <typename t_CParentStream, typename t_CStreamType>
	TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::TCBinaryStream_Encrypted
		(
			CEncryptKeyIV const &_KeyIV
			, EDigestType _HMAC
			, NContainer::CSecureByteVector const &_HMACKey
		)
		: mp_KeyIV(_KeyIV)
		, mp_HMAC(_HMAC)
		, mp_HMACKey(_HMACKey)
		, mp_BlockSize(CEncryptKeyIV::fs_GetBlockSize(_KeyIV.m_Crypto))
	{

	}

	template <typename t_CParentStream, typename t_CStreamType>
	TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::~TCBinaryStream_Encrypted()
	{
		f_Close();
	}

	template <typename t_CParentStream, typename t_CStreamType>
	decltype(auto) TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::fp_GetParentStream() const
	{
		if constexpr (!NTraits::TCIsBaseOf<typename NTraits::TCRemoveReference<t_CParentStream>::CType, NStream::CBinaryStream>::mc_Value)
		{
			if (!mp_Stream)
				DMibErrorCryptography("Stream has not been opened");
			return *mp_Stream;
		}
		else
			return mp_Stream;
	}

	template <typename t_CParentStream, typename t_CStreamType>
	void TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_Close()
	{
		if (mp_OpenFlags == NFile::EFileOpen_None)
			return;

		auto &ParentStream = fp_GetParentStream();

		fp_WriteDirty(true);
		ParentStream.f_Flush(false);
		mp_OpenFlags = NFile::EFileOpen_None;
		NMemory::fg_SecureMemClear(mp_DecryptedBlock.f_GetArray(), mp_DecryptedBlock.f_GetLen());
		mp_pHMACContext.f_Clear();
		mp_pEncryptContext.f_Clear();
		if constexpr (!NTraits::TCIsBaseOf<typename NTraits::TCRemoveReference<t_CParentStream>::CType, NStream::CBinaryStream>::mc_Value)
			mp_Stream = nullptr;
		mp_CurrentLoaded = -1;

	}

	template <typename t_CParentStream, typename t_CStreamType>
	template <typename tf_CParentStream>
	void TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_Open(tf_CParentStream &&_ParentStream, NFile::EFileOpen _OpenFlags)
	{
		mp_Stream = fg_Forward<tf_CParentStream>(_ParentStream);
		auto &ParentStream = fp_GetParentStream();
		if (!ParentStream.f_IsValid())
			DMibErrorCryptography("Stream is not valid");

		// Decrypt can write mp_BlockSize - 1 bytes extra. Allocate extra space for that
		mp_DecryptedBlock.f_SetLen(mp_BufferSize + mp_BlockSize);

		ParentStream.f_SetPosition(0);
		mp_bCurrentDirty = false;
		mp_bCanChangePosition = false;
		mp_bIsCBC = false;
		mp_bIsECB = false;

		switch (mp_KeyIV.m_Crypto)
		{
		case ECryptoType_DES_EDE3_CBC:
		case ECryptoType_AES_128_CBC:
		case ECryptoType_AES_256_CBC:
			mp_bCanChangePosition = true;
			mp_bIsCBC = true;
			break;
		case ECryptoType_AES_128_ECB:
		case ECryptoType_AES_256_ECB:
			mp_bCanChangePosition = true;
			mp_bIsECB = true;
			break;
		}

		if (_OpenFlags == NFile::EFileOpen_Write || _OpenFlags == (NFile::EFileOpen_Read | NFile::EFileOpen_Write))
		{
			mp_FilePos = 0;
			mp_pEncryptContext = fg_Construct(ECryptoFlags_Encrypt | ECryptoFlags_UsePadding, mp_KeyIV);

			if (mp_HMAC != EDigestType_None)
				mp_pHMACContext = fg_Construct<CIncrementalHMAC>(mp_HMAC, mp_HMACKey);
			if (mp_BufferSize < mp_BlockSize)
				DMibErrorCryptography(NStr::fg_Format("Buffer size cannot be smaller than cipher block size: {}", mp_BlockSize));
			mp_OpenFlags = _OpenFlags;
		}
		else if (_OpenFlags == NFile::EFileOpen_Read)
		{
			mp_FilePos = 0;
			mp_EncryptedFileLen = ParentStream.f_GetLength();
			mp_FileLen = mp_EncryptedFileLen;

			mp_pEncryptContext = fg_Construct(ECryptoFlags_Decrypt | ECryptoFlags_UsePadding, mp_KeyIV);
			mint HMACSize = 0;
			if (mp_HMAC != EDigestType_None)
			{
				mp_pHMACContext = fg_Construct(mp_HMAC, mp_HMACKey);
				HMACSize = mp_pHMACContext->f_GetHMACSize();
			}

			if (mp_BufferSize < mp_BlockSize)
				DMibErrorCryptography(NStr::fg_Format("Buffer size cannot be smaller than cipher block size: {}", mp_BlockSize));

			if ((mp_FileLen - NStream::CFilePos(HMACSize)) & (NStream::CFilePos(mp_BlockSize)-1) || mp_FileLen < NStream::CFilePos(HMACSize + mp_BlockSize))
				DMibErrorCryptography("Stream length does not correspond with a properly encoded stream");

			mp_OpenFlags = _OpenFlags;
			if (mp_FileLen > 0)
			{
				// First, deduct the size of the HMAC
				if (mp_HMAC != EDigestType_None)
				{
					mp_FileLen -= HMACSize;
					mp_EncryptedFileLen -= HMACSize;

					// Check the HMAC.
					while (mp_FilePos < mp_EncryptedFileLen)
					{
						mint ThisTime = mint(fg_Min(mp_EncryptedFileLen - mp_FilePos, NStream::CFilePos(mp_BufferSize)));
						DMibCheck(ThisTime <= mp_DecryptedBlock.f_GetLen());
						ParentStream.f_ConsumeBytes(mp_DecryptedBlock.f_GetArray(), ThisTime);
						mp_pHMACContext->f_Update(mp_DecryptedBlock.f_GetArray(), ThisTime);
						mp_FilePos += ThisTime;
					}
					NContainer::CSecureByteVector ComputedHMAC;
					NContainer::CSecureByteVector FileHMAC;
					ParentStream.f_ConsumeBytes(FileHMAC.f_GetArray(HMACSize), HMACSize);
					mp_pHMACContext->f_Finalize(ComputedHMAC.f_GetArray(HMACSize), HMACSize);
					if (ComputedHMAC != FileHMAC)
						DMibErrorCryptography("HMAC mismatch. The file has been tampered with.");
				}
				ParentStream.f_SetPosition(0);
				mp_FilePos = 0;

				if (mp_bCanChangePosition)
				{
					// ECB and CBC cryptos work on mp_BlockSize bytes multiples and the final block of the file has been padded to an even mp_BlockSize byte multiple.
					// Decrypting and finalizing the final block returns how many bytes it contained before encryption.
					NStream::CFilePos Pos = mp_EncryptedFileLen - mp_BlockSize;
					if (Pos >= 0)
					{
						NContainer::CSecureByteVector LastBlock;
						NContainer::CSecureByteVector Decrypted;
						NContainer::CSecureByteVector IV{mp_KeyIV.m_IV};
						ParentStream.f_SetPosition(Pos);
						ParentStream.f_ConsumeBytes(LastBlock.f_GetArray(mp_BlockSize), mp_BlockSize);
						if (mp_bIsCBC)
						{
							// To decrypt the final block CBC ciphers need the second to last block as IV to decrypt the final block.
							if (Pos >= NStream::CFilePos(mp_BlockSize))
							{
								ParentStream.f_SetPosition(Pos - mp_BlockSize);
								ParentStream.f_ConsumeBytes(IV.f_GetArray(mp_BlockSize), mp_BlockSize);
							}
						}
						CIncrementalEncrypt TempDecryptionContext
							(
								ECryptoFlags_Decrypt | ECryptoFlags_UsePadding
								, {mp_KeyIV.m_Key, IV, mp_KeyIV.m_Crypto}
							)
						;

						TempDecryptionContext.f_Decrypt(LastBlock.f_GetArray(), mp_BlockSize, Decrypted.f_GetArray(mp_BlockSize));
						auto nUsedBytes = TempDecryptionContext.f_FinalizePaddedDecrypt(Decrypted.f_GetArray(), mp_BlockSize);
						mp_FileLen = mp_EncryptedFileLen - (mp_BlockSize - nUsedBytes);
					}
				}
				ParentStream.f_SetPosition(0);
			}
		}
		else
		{
			DMibErrorCryptography
				(
					"Unsupported combination of open flags. Use NFile::EFileOpen_Read (random access), NFile::EFileOpen_Write (sequential write), or "
					"NFile::EFileOpen_Read | NFile::EFileOpen_Write (first sequential write, then random access read after first non-sequential f_SetPosition call)"
				)
			;
		}
	}

	template <typename t_CParentStream, typename t_CStreamType>
	void TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::fp_WriteDirty(bool _bFinalize)
	{
		if (!mp_bCurrentDirty && !_bFinalize)
			return;

		auto &ParentStream = fp_GetParentStream();
		if (mp_bCurrentDirty)
		{
			NStream::CFilePos Size = mp_FilePos - mp_CurrentLoaded;
			DMibCheck(Size <= NStream::CFilePos(mp_DecryptedBlock.f_GetLen()));

			// The cipher context can hide one block from us so the first time nBytes can be up to mp_BlockSize bytes short.
			// Don't worry, we will get them back when the stream is finalized.
			mp_TempBlock.f_SetAtLeastLen(Size);
			auto nBytes = mp_pEncryptContext->f_Encrypt(mp_DecryptedBlock.f_GetArray(), Size, mp_TempBlock.f_GetArray());
			if (mp_HMAC != EDigestType_None)
				mp_pHMACContext->f_Update(mp_TempBlock.f_GetArray(), nBytes);
			ParentStream.f_FeedBytes(mp_TempBlock.f_GetArray(), nBytes);

			mp_bCurrentDirty = false;
			mp_bNeedsFinalization = true;
			mp_EncryptedFileLen += nBytes;
		}

		// The ECB and CBC cryptos work on mp_BlockSize bytes blocks (typically 16 bytes) so the final block undergoes "finalization", i.e. the final block is padded to a full
		// mp_BlockSize bytes block.  To do this the crypto context holds on to the last up to mp_BlockSize bytes and doesn't return them until the encryption is finalized.
		// In the worst case it can produce 2 * mp_BlockSize bytes, make sure we have allocated that much memory.
		//
		// Once the encrypted data is finalized a HMAC will be written to the stream.
		if (_bFinalize && mp_bNeedsFinalization)
		{
			if (mp_BlockSize > 1)
			{
				mp_TempBlock.f_SetAtLeastLen(mp_BlockSize * 2);
				auto nBytes = mp_pEncryptContext->f_FinalizePaddedEncrypt(mp_TempBlock.f_GetArray(), mp_BlockSize * 2);
				ParentStream.f_FeedBytes(mp_TempBlock.f_GetArray(), nBytes);
				if (mp_HMAC != EDigestType_None)
				{
					mp_pHMACContext->f_Update(mp_TempBlock.f_GetArray(), nBytes);
					mp_EncryptedFileLen += nBytes;
				}
			}

			if (mp_HMAC != EDigestType_None)
			{
				auto HMACSize = mp_pHMACContext->f_GetHMACSize();
				mp_TempBlock.f_SetAtLeastLen(HMACSize);
				auto nBytes = mp_pHMACContext->f_Finalize(mp_TempBlock.f_GetArray(), HMACSize);
				ParentStream.f_FeedBytes(mp_TempBlock.f_GetArray(), nBytes);
				mp_EncryptedFileLen += nBytes;
			}

			mp_bNeedsFinalization = false;
		}
	}

	template <typename t_CParentStream, typename t_CStreamType>
	mint TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::fp_PrepareBlock(NStream::CFilePos _Pos, bint _bWrite)
	{
		if (mp_CurrentLoaded >= 0 && _Pos >=  mp_CurrentLoaded && _Pos < (mp_CurrentLoaded + NStream::CFilePos(mp_BufferSize)))
		{
			return _Pos - mp_CurrentLoaded;
		}

		fp_WriteDirty(false);

		auto &ParentStream = fp_GetParentStream();
		NStream::CFilePos BlockPos = _Pos & (NStream::CFilePos(mp_BufferSize) - 1);
		mp_CurrentLoaded = _Pos - BlockPos;

		if (_Pos + 1 > mp_FileLen)
		{
			if (_bWrite)
			{
				DMibCheck(mp_BufferSize + mp_BlockSize <= mp_DecryptedBlock.f_GetLen());
				NMemory::fg_SecureMemClear(mp_DecryptedBlock.f_GetArray(), mp_BufferSize + mp_BlockSize);
			}
			else
				DMibErrorCryptography("Read past end of file");
		}
		else if (mp_EncryptedFileLen > 0)
		{
			mint ThisTime = mint(fg_Min(mp_EncryptedFileLen - mp_CurrentLoaded, NStream::CFilePos(mp_BufferSize)));
			mint DecryptedBytes = 0;

			if (mp_CurrentLoaded != mp_LastLoaded)
			{
				if (mp_CurrentLoaded > 0)
				{
					if (!mp_bCanChangePosition)
						DMibErrorCryptography("Crypto does not support random read access");

					if (mp_bIsCBC)
					{
						// Pick up IV from the block before mp_CurrentLoaded and reinitialize the context
						ParentStream.f_SetPosition(mp_CurrentLoaded - mp_BlockSize);
						NContainer::CSecureByteVector IV;
						ParentStream.f_ConsumeBytes(IV.f_GetArray(mp_BlockSize), mp_BlockSize);
						CEncryptKeyIV KeyIV{mp_KeyIV.m_Key, IV, mp_KeyIV.m_Crypto};
						mp_pEncryptContext = fg_Construct(ECryptoFlags_Decrypt | ECryptoFlags_UsePadding, KeyIV);
					}
					else
					{
						ParentStream.f_SetPosition(mp_CurrentLoaded);
						mp_pEncryptContext = fg_Construct(ECryptoFlags_Decrypt | ECryptoFlags_UsePadding, mp_KeyIV);
					}
				}
				else if (mp_LastLoaded != 0)
				{
					// SetPosition must have rewinded the file, restart with original IV
					ParentStream.f_SetPosition(0);
					mp_pEncryptContext = fg_Construct(ECryptoFlags_Decrypt | ECryptoFlags_UsePadding, mp_KeyIV);
				}
			}
			mp_TempBlock.f_SetAtLeastLen(ThisTime + mp_BlockSize);
			ParentStream.f_ConsumeBytes(mp_TempBlock.f_GetArray(), ThisTime);
			DMibCheck(ThisTime <= mp_DecryptedBlock.f_GetLen());
			DecryptedBytes = mp_pEncryptContext->f_Decrypt(mp_TempBlock.f_GetArray(), ThisTime, mp_DecryptedBlock.f_GetArray());

			if (ThisTime != mp_BufferSize && mp_BlockSize > 1)
			{
				mint nRemainingBytes = ThisTime - DecryptedBytes;
				DMibCheck((ThisTime + nRemainingBytes) <= mp_DecryptedBlock.f_GetLen());
				DecryptedBytes += mp_pEncryptContext->f_FinalizePaddedDecrypt(mp_DecryptedBlock.f_GetArray() + DecryptedBytes, nRemainingBytes);
			}

			mp_LastLoaded = mp_CurrentLoaded + DecryptedBytes;
		}

		return _Pos - mp_CurrentLoaded;
	}

	template <typename t_CParentStream, typename t_CStreamType>
	void TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_FeedBytes(const void *_pMem, mint _nBytes)
	{
		if (!(mp_OpenFlags & NFile::EFileOpen_Write))
			DMibErrorCryptography("Stream not opened for write");

		const uint8 *pMem = (const uint8 *)_pMem;
		while (_nBytes)
		{
			mint Pos = fp_PrepareBlock(mp_FilePos, true);
			mint ThisTime = fg_Min(_nBytes, mp_BufferSize - Pos);
			DMibCheck(Pos + ThisTime <= mp_DecryptedBlock.f_GetLen());
			NMemory::fg_MemCopy(mp_DecryptedBlock.f_GetArray() + Pos, pMem, ThisTime);
			mp_bCurrentDirty = true;

			mp_FilePos += ThisTime;
			pMem += ThisTime;
			_nBytes -= ThisTime;
			if (mp_FilePos > mp_FileLen)
				mp_FileLen = mp_FilePos;
		}
	}

	template <typename t_CParentStream, typename t_CStreamType>
	void TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_ConsumeBytes(void *_pMem, mint _nBytes)
	{
		if (!(mp_OpenFlags & NFile::EFileOpen_Read))
			DMibErrorCryptography("Stream not opened for read");

		if (mp_FilePos + NStream::CFilePos(_nBytes) > mp_FileLen)
			DMibErrorCryptography("Read past end of file");

		uint8 *pMem = (uint8 *)_pMem;
		while (_nBytes)
		{
			mint Pos = fp_PrepareBlock(mp_FilePos, false);
			mint ThisTime = fg_Min(_nBytes, mp_BufferSize - Pos);
			DMibCheck(Pos + ThisTime <= mp_DecryptedBlock.f_GetLen());
			NMemory::fg_MemCopy(pMem, mp_DecryptedBlock.f_GetArray() + Pos, ThisTime);

			mp_FilePos += ThisTime;
			pMem += ThisTime;
			_nBytes -= ThisTime;
		}
	}

	template <typename t_CParentStream, typename t_CStreamType>
	bint TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_IsValid() const
	{
		auto &ParentStream = fp_GetParentStream();
		return ParentStream.f_IsValid();
	}

	template <typename t_CParentStream, typename t_CStreamType>
	bint TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_IsAtEndOfStream() const
	{
		return mp_FilePos >= mp_FileLen;
	}

	template <typename t_CParentStream, typename t_CStreamType>
	NStream::CFilePos TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_GetPosition() const
	{
		return mp_FilePos;
	}

	template <typename t_CParentStream, typename t_CStreamType>
	void TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_SetPosition(NStream::CFilePos _Pos)
	{
		// This is a no-op and can be handled in all modes
		if (mp_FilePos == _Pos)
			return;

		// In pure write mode, no other set position operations can be accepted
		if (mp_OpenFlags == NFile::EFileOpen_Write)
			DMibErrorCryptography("Stream does not support positioning during write");

		// In "write then read" mode, any non-sequential set position operation turns the stream into a read mode.
		// Flush and finalize what has been written, then make it a pure read stream
		if (mp_OpenFlags == (NFile::EFileOpen_Read | NFile::EFileOpen_Write))
		{
			fp_WriteDirty(true);
			mp_OpenFlags = NFile::EFileOpen_Read;
			// Make sure the buffer is reloaded and the AES context is reinitialized for decryption
			mp_LastLoaded = -2;
			mp_CurrentLoaded = -1;
		}

		mp_FilePos = _Pos;
	}

	template <typename t_CParentStream, typename t_CStreamType>
	void TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_SetPositionFromEnd(NStream::CFilePos _Pos)
	{
		if (mp_OpenFlags & NFile::EFileOpen_Write)
			DMibErrorCryptography("Stream does not support positioning during write");

		mp_FilePos = mp_FileLen - _Pos;
	}

	template <typename t_CParentStream, typename t_CStreamType>
	void TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_AddPosition(NStream::CFilePos _Pos)
	{
		if (mp_OpenFlags & NFile::EFileOpen_Write)
			DMibErrorCryptography("Stream does not support positioning during write");

		mp_FilePos += _Pos;
	}

	template <typename t_CParentStream, typename t_CStreamType>
	bint TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_IsValidReadPosition(NStream::CFilePos _Pos) const
	{
		return _Pos >= 0 && _Pos < mp_FilePos;
	}

	template <typename t_CParentStream, typename t_CStreamType>
	void TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_Flush(bint _bLocalCacheOnly)
	{
		fp_WriteDirty(false);

		auto &ParentStream = fp_GetParentStream();
		return ParentStream.f_Flush(_bLocalCacheOnly);
	}

	template <typename t_CParentStream, typename t_CStreamType>
	void TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_SetCacheSize(mint _CacheSize)
	{
		auto &ParentStream = fp_GetParentStream();
		return ParentStream.f_SetCacheSize(_CacheSize);
	}

	template <typename t_CParentStream, typename t_CStreamType>
	NStream::CFilePos TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_GetLength() const
	{
		auto &ParentStream = fp_GetParentStream();
		if (mp_OpenFlags & NFile::EFileOpen_Write)
			return fg_Max(ParentStream.f_GetLength(), fg_Max(mp_CurrentLoaded, mp_FilePos));
		else
			return mp_FileLen;
	}

	template <typename t_CParentStream, typename t_CStreamType>
	mint TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_ContainerLengthLimit() const
	{
		return NStream::fg_CapLengthLimit(f_GetLength() - f_GetPosition());
	}

	template <typename t_CParentStream, typename t_CStreamType>
	void TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_SetLength(NStream::CFilePos _Length)
	{
		fp_WriteDirty(true);

		// The encryption works with 16 byte blocks and the stream will be padded to a multiple of the block size.
		// Use the length of the encrypted stream instead, if it was the full file length.
		// We cannot support random seeks for security reasons when the file is open for write.
		if (mp_OpenFlags & NFile::EFileOpen_Write)
		{
			if (_Length != mp_FileLen)
				DMibErrorCryptography("TCBinaryStream_Encrypted::f_SetLength: Operation not supported for other lengths than the full file length");
			_Length = mp_EncryptedFileLen;
		}

		auto &ParentStream = fp_GetParentStream();
		ParentStream.f_SetLength(_Length);
	}

	template <typename t_CParentStream, typename t_CStreamType>
	void TCBinaryStream_Encrypted<t_CParentStream, t_CStreamType>::f_SetBufferSize(mint _BufferSize)
	{
		if (mp_OpenFlags != NFile::EFileOpen_None)
			DMibErrorCryptography("Cannot resize buffer on an open stream");

		if (!fg_IsPowerOfTwo(_BufferSize))
			DMibErrorCryptography("Buffer size must be a power of 2");

		mp_BufferSize = _BufferSize;
	}
}
