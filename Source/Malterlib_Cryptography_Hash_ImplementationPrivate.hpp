// Copyright © 2015 Hansoft AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

namespace NMib::NCryptography
{
	template <typename t_CHashImpl>
	TCHashImpl<t_CHashImpl>::TCHashImpl() = default;

	template <typename t_CHashImpl>
	TCHashImpl<t_CHashImpl>::TCHashImpl(TCHashImpl const &) = default;

	template <typename t_CHashImpl>
	TCHashImpl<t_CHashImpl>::TCHashImpl(TCHashImpl &&) = default;

	template <typename t_CHashImpl>
	auto TCHashImpl<t_CHashImpl>::operator = (TCHashImpl const &) -> TCHashImpl & = default;

	template <typename t_CHashImpl>
	auto TCHashImpl<t_CHashImpl>::operator = (TCHashImpl &&) -> TCHashImpl & = default;

	template <typename t_CHashImpl>
	void TCHashImpl<t_CHashImpl>::f_Reset()
	{
		mp_Implementation.f_Reset();
	}

	template <typename t_CHashImpl>
	auto TCHashImpl<t_CHashImpl>::fs_DigestFromData(void const *_pData, umint _Len) -> CMessageDigest
	{
		CMessageDigest Ret;
		TCHashImpl Hash;
		Hash.f_AddData(_pData, _Len);
		Ret = Hash;
		return Ret;
	}

	template <typename t_CHashImpl>
	auto TCHashImpl<t_CHashImpl>::fs_DigestFromData(NContainer::CByteVector const &_Data) -> CMessageDigest
	{
		CMessageDigest Ret;
		TCHashImpl Hash;
		Hash.f_AddData(_Data.f_GetArray(), _Data.f_GetLen());
		Ret = Hash;
		return Ret;
	}

	template <typename t_CHashImpl>
	auto TCHashImpl<t_CHashImpl>::fs_DigestFromData(NContainer::CSecureByteVector const &_Data) -> CMessageDigest
	{
		CMessageDigest Ret;
		TCHashImpl Hash;
		Hash.f_AddData(_Data.f_GetArray(), _Data.f_GetLen());
		Ret = Hash;
		return Ret;
	}

	template <typename t_CHashImpl>
	auto TCHashImpl<t_CHashImpl>::fs_DigestFromStream(NStream::CBinaryStream &_Stream) -> CMessageDigest
	{
		CMessageDigest Ret;
		TCHashImpl Hash;

		CMibFilePos Length = _Stream.f_GetLength();

		NFile::CFileIoTempBuffer Buffer;

		while (Length)
		{
			auto BufferResult = Buffer.f_UseBuffer(Length);
			_Stream.f_ConsumeBytes(BufferResult.m_pBuffer, BufferResult.m_nBytes);
			Hash.f_AddData(BufferResult.m_pBuffer, BufferResult.m_nBytes);

			Length -= BufferResult.m_nBytes;
		}
		Ret = Hash;
		return Ret;
	}
}
