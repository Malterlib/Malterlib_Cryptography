// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

#include <Mib/Core/Core>
#include <Mib/Cryptography/Hash>

namespace NMib
{
	namespace NDataProcessing
	{

		class CHashImpl_MD5
		{
		public:

			typedef uint32 CData;

			enum
			{
				EBlockSize = 64/sizeof(CData),
				EDigestSize = 16
			};
			class CState
			{
			public:
				CData m_State[4];
			};
			static void fs_InitState(CState &_State)
			{
				_State.m_State[0] = 0x67452301;
				_State.m_State[1] = 0xefcdab89;
				_State.m_State[2] = 0x98badcfe;
				_State.m_State[3] = 0x10325476;
			}

			static void fs_Transform(CState &_State, const CData *_pData)
			{
				uint32 State0 = _State.m_State[0];
				uint32 State1 = _State.m_State[1];
				uint32 State2 = _State.m_State[2];
				uint32 State3 = _State.m_State[3];
				uint32 Block00;
				uint32 Block01;
				uint32 Block02;
				uint32 Block03;
				uint32 Block04;
				uint32 Block05;
				uint32 Block06;
				uint32 Block07;
				uint32 Block08;
				uint32 Block09;
				uint32 Block10;
				uint32 Block11;
				uint32 Block12;
				uint32 Block13;
				uint32 Block14;
				uint32 Block15;

				State0 = fsp_Transform0 (State0, State1, State2, State3, Block00 = fg_ByteSwapLE(_pData[ 0]), 7 , 0xd76aa478);
				State3 = fsp_Transform0 (State3, State0, State1, State2, Block01 = fg_ByteSwapLE(_pData[ 1]), 12, 0xe8c7b756);
				State2 = fsp_Transform0 (State2, State3, State0, State1, Block02 = fg_ByteSwapLE(_pData[ 2]), 17, 0x242070db);
				State1 = fsp_Transform0 (State1, State2, State3, State0, Block03 = fg_ByteSwapLE(_pData[ 3]), 22, 0xc1bdceee);
				State0 = fsp_Transform0 (State0, State1, State2, State3, Block04 = fg_ByteSwapLE(_pData[ 4]), 7 , 0xf57c0faf);
				State3 = fsp_Transform0 (State3, State0, State1, State2, Block05 = fg_ByteSwapLE(_pData[ 5]), 12, 0x4787c62a);
				State2 = fsp_Transform0 (State2, State3, State0, State1, Block06 = fg_ByteSwapLE(_pData[ 6]), 17, 0xa8304613);
				State1 = fsp_Transform0 (State1, State2, State3, State0, Block07 = fg_ByteSwapLE(_pData[ 7]), 22, 0xfd469501);
				State0 = fsp_Transform0 (State0, State1, State2, State3, Block08 = fg_ByteSwapLE(_pData[ 8]), 7 , 0x698098d8);
				State3 = fsp_Transform0 (State3, State0, State1, State2, Block09 = fg_ByteSwapLE(_pData[ 9]), 12, 0x8b44f7af);
				State2 = fsp_Transform0 (State2, State3, State0, State1, Block10 = fg_ByteSwapLE(_pData[10]), 17, 0xffff5bb1);
				State1 = fsp_Transform0 (State1, State2, State3, State0, Block11 = fg_ByteSwapLE(_pData[11]), 22, 0x895cd7be);
				State0 = fsp_Transform0 (State0, State1, State2, State3, Block12 = fg_ByteSwapLE(_pData[12]), 7 , 0x6b901122);
				State3 = fsp_Transform0 (State3, State0, State1, State2, Block13 = fg_ByteSwapLE(_pData[13]), 12, 0xfd987193);
				State2 = fsp_Transform0 (State2, State3, State0, State1, Block14 = fg_ByteSwapLE(_pData[14]), 17, 0xa679438e);
				State1 = fsp_Transform0 (State1, State2, State3, State0, Block15 = fg_ByteSwapLE(_pData[15]), 22, 0x49b40821);

				State0 = fsp_Transform1 (State0, State1, State2, State3, Block01, 5 , 0xf61e2562);
				State3 = fsp_Transform1 (State3, State0, State1, State2, Block06, 9 , 0xc040b340);
				State2 = fsp_Transform1 (State2, State3, State0, State1, Block11, 14, 0x265e5a51);
				State1 = fsp_Transform1 (State1, State2, State3, State0, Block00, 20, 0xe9b6c7aa);
				State0 = fsp_Transform1 (State0, State1, State2, State3, Block05, 5 , 0xd62f105d);
				State3 = fsp_Transform1 (State3, State0, State1, State2, Block10, 9 ,  0x2441453);
				State2 = fsp_Transform1 (State2, State3, State0, State1, Block15, 14, 0xd8a1e681);
				State1 = fsp_Transform1 (State1, State2, State3, State0, Block04, 20, 0xe7d3fbc8);
				State0 = fsp_Transform1 (State0, State1, State2, State3, Block09, 5 , 0x21e1cde6);
				State3 = fsp_Transform1 (State3, State0, State1, State2, Block14, 9 , 0xc33707d6);
				State2 = fsp_Transform1 (State2, State3, State0, State1, Block03, 14, 0xf4d50d87);
				State1 = fsp_Transform1 (State1, State2, State3, State0, Block08, 20, 0x455a14ed);
				State0 = fsp_Transform1 (State0, State1, State2, State3, Block13, 5 , 0xa9e3e905);
				State3 = fsp_Transform1 (State3, State0, State1, State2, Block02, 9 , 0xfcefa3f8);
				State2 = fsp_Transform1 (State2, State3, State0, State1, Block07, 14, 0x676f02d9);
				State1 = fsp_Transform1 (State1, State2, State3, State0, Block12, 20, 0x8d2a4c8a);

				State0 = fsp_Transform2 (State0, State1, State2, State3, Block05, 4 , 0xfffa3942);
				State3 = fsp_Transform2 (State3, State0, State1, State2, Block08, 11, 0x8771f681);
				State2 = fsp_Transform2 (State2, State3, State0, State1, Block11, 16, 0x6d9d6122);
				State1 = fsp_Transform2 (State1, State2, State3, State0, Block14, 23, 0xfde5380c);
				State0 = fsp_Transform2 (State0, State1, State2, State3, Block01, 4 , 0xa4beea44);
				State3 = fsp_Transform2 (State3, State0, State1, State2, Block04, 11, 0x4bdecfa9);
				State2 = fsp_Transform2 (State2, State3, State0, State1, Block07, 16, 0xf6bb4b60);
				State1 = fsp_Transform2 (State1, State2, State3, State0, Block10, 23, 0xbebfbc70);
				State0 = fsp_Transform2 (State0, State1, State2, State3, Block13, 4 , 0x289b7ec6);
				State3 = fsp_Transform2 (State3, State0, State1, State2, Block00, 11, 0xeaa127fa);
				State2 = fsp_Transform2 (State2, State3, State0, State1, Block03, 16, 0xd4ef3085);
				State1 = fsp_Transform2 (State1, State2, State3, State0, Block06, 23,  0x4881d05);
				State0 = fsp_Transform2 (State0, State1, State2, State3, Block09, 4 , 0xd9d4d039);
				State3 = fsp_Transform2 (State3, State0, State1, State2, Block12, 11, 0xe6db99e5);
				State2 = fsp_Transform2 (State2, State3, State0, State1, Block15, 16, 0x1fa27cf8);
				State1 = fsp_Transform2 (State1, State2, State3, State0, Block02, 23, 0xc4ac5665);

				State0 = fsp_Transform3 (State0, State1, State2, State3, Block00, 6 , 0xf4292244);
				State3 = fsp_Transform3 (State3, State0, State1, State2, Block07, 10, 0x432aff97);
				State2 = fsp_Transform3 (State2, State3, State0, State1, Block14, 15, 0xab9423a7);
				State1 = fsp_Transform3 (State1, State2, State3, State0, Block05, 21, 0xfc93a039);
				State0 = fsp_Transform3 (State0, State1, State2, State3, Block12, 6 , 0x655b59c3);
				State3 = fsp_Transform3 (State3, State0, State1, State2, Block03, 10, 0x8f0ccc92);
				State2 = fsp_Transform3 (State2, State3, State0, State1, Block10, 15, 0xffeff47d);
				State1 = fsp_Transform3 (State1, State2, State3, State0, Block01, 21, 0x85845dd1);
				State0 = fsp_Transform3 (State0, State1, State2, State3, Block08, 6 , 0x6fa87e4f);
				State3 = fsp_Transform3 (State3, State0, State1, State2, Block15, 10, 0xfe2ce6e0);
				State2 = fsp_Transform3 (State2, State3, State0, State1, Block06, 15, 0xa3014314);
				State1 = fsp_Transform3 (State1, State2, State3, State0, Block13, 21, 0x4e0811a1);
				State0 = fsp_Transform3 (State0, State1, State2, State3, Block04, 6 , 0xf7537e82);
				State3 = fsp_Transform3 (State3, State0, State1, State2, Block11, 10, 0xbd3af235);
				State2 = fsp_Transform3 (State2, State3, State0, State1, Block02, 15, 0x2ad7d2bb);
				State1 = fsp_Transform3 (State1, State2, State3, State0, Block09, 21, 0xeb86d391);

				Block00 = 0; Block01 = 0; Block02 = 0; Block03 = 0;
				Block04 = 0; Block05 = 0; Block06 = 0; Block07 = 0;
				Block08 = 0; Block09 = 0; Block10 = 0; Block11 = 0;
				Block12 = 0; Block13 = 0; Block14 = 0; Block15 = 0;
//				NMem::fg_ObjectSet(Block, uint32(0), 16);
				_State.m_State[0] += State0;
				_State.m_State[1] += State1;
				_State.m_State[2] += State2;
				_State.m_State[3] += State3;
				State0 = 0;
				State1 = 0;
				State2 = 0;
				State3 = 0;
//				NMem::fg_ObjectSet(State, uint32(0), 4);

			}

			template <typename tf_CHashImpl>
			static void fs_GetDigest(const tf_CHashImpl &_Impl, typename tf_CHashImpl::CMessageDigest &_Digest)
			{
				tf_CHashImpl TempState(_Impl);

#ifdef DMibPLittleEndian
				static uint32 Pad[64/sizeof(uint32)] = {constant_uint64(0x00000080), 0};
#else
				static uint32 Pad[64/sizeof(uint32)] = {constant_uint64(0x80000000), 0};
#endif
				uint64 Size = fg_ByteSwapLE((TempState.m_nBytes % (constant_int64(0x1fffffffffffffff))) * 8);
				int Offset = (TempState.m_nBytes & 0x3f);

				TempState.f_AddData(Pad, (Offset < 56) ? (56 - Offset) : (120 - Offset));
				TempState.f_AddData(&Size, sizeof(Size));

				uint32 *pData = (uint32 *)_Digest.f_GetData();
				pData[0] = fg_ByteSwapLE(TempState.m_State.m_State[0]);
				pData[1] = fg_ByteSwapLE(TempState.m_State.m_State[1]);
				pData[2] = fg_ByteSwapLE(TempState.m_State.m_State[2]);
				pData[3] = fg_ByteSwapLE(TempState.m_State.m_State[3]);
			}
		private:
			static inline_small uint32 fsp_Transform0(uint32 _Input0, uint32 _Input1, uint32 _Input2, uint32 _Input3, uint32 _Data, uint32 _Rotate, uint32 _Add) 
			{
//				return fg_RotateLeft(_Input0 + (((_Input1 & _Input2) | ((~_Input1) & _Input3)) + _Data + _Add), _Rotate) + _Input1;
				return fg_RotateLeft(_Input0 + ((((_Input2 ^ _Input3) & _Input1) ^ _Input3) + _Data + _Add), _Rotate) + _Input1;
			}
			static inline_small uint32 fsp_Transform1(uint32 _Input0, uint32 _Input1, uint32 _Input2, uint32 _Input3, uint32 _Data, uint32 _Rotate, uint32 _Add) 
			{
//				return fg_RotateLeft(_Input0 + (((_Input1 & _Input3) | (_Input2 & (~_Input3))) + _Data + _Add), _Rotate) + _Input1;
				return fg_RotateLeft(_Input0 + ((((_Input1 ^ _Input2) & _Input3) ^ _Input2) + _Data + _Add), _Rotate) + _Input1;
			}
			static inline_small uint32 fsp_Transform2(uint32 _Input0, uint32 _Input1, uint32 _Input2, uint32 _Input3, uint32 _Data, uint32 _Rotate, uint32 _Add) 
			{
				return fg_RotateLeft(_Input0 + ((_Input1 ^ _Input2 ^ _Input3) + _Data + _Add), _Rotate) + _Input1;
			}
			static inline_small uint32 fsp_Transform3(uint32 _Input0, uint32 _Input1, uint32 _Input2, uint32 _Input3, uint32 _Data, uint32 _Rotate, uint32 _Add) 
			{
				return fg_RotateLeft(_Input0 + ((_Input2 ^ (_Input1 | (~_Input3))) + _Data + _Add), _Rotate) + _Input1;
			}
		};

		typedef TCHashImpl<CHashImpl_MD5> CHash_MD5;
		typedef CHash_MD5::CMessageDigest CHashDigest_MD5;

		class CHashCache
		{
			NStr::CStr mp_HashFileName;
			bool mp_bUpdateHash;
			bool mp_bAlwaysCheckHash;
			NContainer::TCMap<NStr::CStr, CHashDigest_MD5> mp_CachedDigests;
			NThread::CMutual mp_Lock;
			
		public:
			CHashCache(NStr::CStr const &_File, bool _bUpdateHash, bool _bAlwaysCheckHash);
			~CHashCache();
			
			bool f_SetAlwaysCheckHash(bool _bAlwaysCheck);
			
			void f_SaveToFile(NStr::CStr const &_File);
			CHashDigest_MD5 f_GetHash(NStr::CStr const &_FileName, NStr::CStr const &_AlternateFileName = NStr::CStr());
			void f_SetHash(NStr::CStr const &_FileName, CHashDigest_MD5 const &_Digest);
		};
		
	}
}

#ifndef DMibPNoShortCuts
using namespace NMib::NDataProcessing;
#endif
