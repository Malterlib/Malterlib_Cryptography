// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

#include <Mib/Core/Core>
#include "Malterlib_Cryptography_Hash.h"

namespace NMib
{
	namespace NDataProcessing
	{

		// start of Steve Reid's code

		class CHashImpl_SHA1
		{
		public:

			typedef uint32 CData;

			enum
			{
				EBlockSize = 64/sizeof(CData),
				EDigestSize = 20
			};
			class CState
			{
			public:
				CData m_State[5];
			};
			static void fs_InitState(CState &_State)
			{
				_State.m_State[0] = 0x67452301L;
				_State.m_State[1] = 0xEFCDAB89L;
				_State.m_State[2] = 0x98BADCFEL;
				_State.m_State[3] = 0x10325476L;
				_State.m_State[4] = 0xC3D2E1F0L;
			}

#			define DMibTemp_Block0(d_iData) (W[d_iData] = fg_ByteSwapBE(_pData[d_iData]))
#			define DMibTemp_Block1(d_iData) (W[d_iData&15] = fg_RotateLeft(W[(d_iData+13)&15]^W[(d_iData+8)&15]^W[(d_iData+2)&15]^W[d_iData&15],1))

#			define DMibTemp_F1(d_X,d_Y,d_Z) (d_Z^(d_X&(d_Y^d_Z)))
#			define DMibTemp_F2(d_X,d_Y,d_Z) (d_X^d_Y^d_Z)
#			define DMibTemp_F3(d_X,d_Y,d_Z) ((d_X&d_Y)|(d_Z&(d_X|d_Y)))
#			define DMibTemp_F4(d_X,d_Y,d_Z) (d_X^d_Y^d_Z)

			// (R0+R1), R2, R3, R4 are the different operations used in SHA1
#			define DMibTemp_R0(d_V,d_W,d_X,d_Y,d_Z,d_iData) d_Z+=DMibTemp_F1(d_W,d_X,d_Y)+DMibTemp_Block0(d_iData)+0x5A827999+fg_RotateLeft(d_V,5);d_W=fg_RotateLeft(d_W,30);
#			define DMibTemp_R1(d_V,d_W,d_X,d_Y,d_Z,d_iData) d_Z+=DMibTemp_F1(d_W,d_X,d_Y)+DMibTemp_Block1(d_iData)+0x5A827999+fg_RotateLeft(d_V,5);d_W=fg_RotateLeft(d_W,30);
#			define DMibTemp_R2(d_V,d_W,d_X,d_Y,d_Z,d_iData) d_Z+=DMibTemp_F2(d_W,d_X,d_Y)+DMibTemp_Block1(d_iData)+0x6ED9EBA1+fg_RotateLeft(d_V,5);d_W=fg_RotateLeft(d_W,30);
#			define DMibTemp_R3(d_V,d_W,d_X,d_Y,d_Z,d_iData) d_Z+=DMibTemp_F3(d_W,d_X,d_Y)+DMibTemp_Block1(d_iData)+0x8F1BBCDC+fg_RotateLeft(d_V,5);d_W=fg_RotateLeft(d_W,30);
#			define DMibTemp_R4(d_V,d_W,d_X,d_Y,d_Z,d_iData) d_Z+=DMibTemp_F4(d_W,d_X,d_Y)+DMibTemp_Block1(d_iData)+0xCA62C1D6+fg_RotateLeft(d_V,5);d_W=fg_RotateLeft(d_W,30);

			static void fs_Transform(CState &_State, const CData *_pData)
			{
				uint32 W[16];
				/* Copy context->state[] to working vars */
				uint32 a = _State.m_State[0];
				uint32 b = _State.m_State[1];
				uint32 c = _State.m_State[2];
				uint32 d = _State.m_State[3];
				uint32 e = _State.m_State[4];
				/* 4 rounds of 20 operations each. Loop unrolled. */
				DMibTemp_R0(a,b,c,d,e, 0); DMibTemp_R0(e,a,b,c,d, 1); DMibTemp_R0(d,e,a,b,c, 2); DMibTemp_R0(c,d,e,a,b, 3);
				DMibTemp_R0(b,c,d,e,a, 4); DMibTemp_R0(a,b,c,d,e, 5); DMibTemp_R0(e,a,b,c,d, 6); DMibTemp_R0(d,e,a,b,c, 7);
				DMibTemp_R0(c,d,e,a,b, 8); DMibTemp_R0(b,c,d,e,a, 9); DMibTemp_R0(a,b,c,d,e,10); DMibTemp_R0(e,a,b,c,d,11);
				DMibTemp_R0(d,e,a,b,c,12); DMibTemp_R0(c,d,e,a,b,13); DMibTemp_R0(b,c,d,e,a,14); DMibTemp_R0(a,b,c,d,e,15);
				DMibTemp_R1(e,a,b,c,d,16); DMibTemp_R1(d,e,a,b,c,17); DMibTemp_R1(c,d,e,a,b,18); DMibTemp_R1(b,c,d,e,a,19);
				DMibTemp_R2(a,b,c,d,e,20); DMibTemp_R2(e,a,b,c,d,21); DMibTemp_R2(d,e,a,b,c,22); DMibTemp_R2(c,d,e,a,b,23);
				DMibTemp_R2(b,c,d,e,a,24); DMibTemp_R2(a,b,c,d,e,25); DMibTemp_R2(e,a,b,c,d,26); DMibTemp_R2(d,e,a,b,c,27);
				DMibTemp_R2(c,d,e,a,b,28); DMibTemp_R2(b,c,d,e,a,29); DMibTemp_R2(a,b,c,d,e,30); DMibTemp_R2(e,a,b,c,d,31);
				DMibTemp_R2(d,e,a,b,c,32); DMibTemp_R2(c,d,e,a,b,33); DMibTemp_R2(b,c,d,e,a,34); DMibTemp_R2(a,b,c,d,e,35);
				DMibTemp_R2(e,a,b,c,d,36); DMibTemp_R2(d,e,a,b,c,37); DMibTemp_R2(c,d,e,a,b,38); DMibTemp_R2(b,c,d,e,a,39);
				DMibTemp_R3(a,b,c,d,e,40); DMibTemp_R3(e,a,b,c,d,41); DMibTemp_R3(d,e,a,b,c,42); DMibTemp_R3(c,d,e,a,b,43);
				DMibTemp_R3(b,c,d,e,a,44); DMibTemp_R3(a,b,c,d,e,45); DMibTemp_R3(e,a,b,c,d,46); DMibTemp_R3(d,e,a,b,c,47);
				DMibTemp_R3(c,d,e,a,b,48); DMibTemp_R3(b,c,d,e,a,49); DMibTemp_R3(a,b,c,d,e,50); DMibTemp_R3(e,a,b,c,d,51);
				DMibTemp_R3(d,e,a,b,c,52); DMibTemp_R3(c,d,e,a,b,53); DMibTemp_R3(b,c,d,e,a,54); DMibTemp_R3(a,b,c,d,e,55);
				DMibTemp_R3(e,a,b,c,d,56); DMibTemp_R3(d,e,a,b,c,57); DMibTemp_R3(c,d,e,a,b,58); DMibTemp_R3(b,c,d,e,a,59);
				DMibTemp_R4(a,b,c,d,e,60); DMibTemp_R4(e,a,b,c,d,61); DMibTemp_R4(d,e,a,b,c,62); DMibTemp_R4(c,d,e,a,b,63);
				DMibTemp_R4(b,c,d,e,a,64); DMibTemp_R4(a,b,c,d,e,65); DMibTemp_R4(e,a,b,c,d,66); DMibTemp_R4(d,e,a,b,c,67);
				DMibTemp_R4(c,d,e,a,b,68); DMibTemp_R4(b,c,d,e,a,69); DMibTemp_R4(a,b,c,d,e,70); DMibTemp_R4(e,a,b,c,d,71);
				DMibTemp_R4(d,e,a,b,c,72); DMibTemp_R4(c,d,e,a,b,73); DMibTemp_R4(b,c,d,e,a,74); DMibTemp_R4(a,b,c,d,e,75);
				DMibTemp_R4(e,a,b,c,d,76); DMibTemp_R4(d,e,a,b,c,77); DMibTemp_R4(c,d,e,a,b,78); DMibTemp_R4(b,c,d,e,a,79);
				// Add the working vars back into state
				W[0] = W[1] = W[3] = W[4] = W[5] = W[6] = W[7] = W[8] = W[9] = W[10] = W[11] = W[12] = W[13] = W[14] = W[15] = 0;
				_State.m_State[0] += a;
				_State.m_State[1] += b;
				_State.m_State[2] += c;
				_State.m_State[3] += d;
				_State.m_State[4] += e;
				// Wipe variables
				a = b = c = d = e = 0;
			}
#			undef DMibTemp_Block0
#			undef DMibTemp_Block1
#			undef DMibTemp_F1
#			undef DMibTemp_F2
#			undef DMibTemp_F3
#			undef DMibTemp_F4
#			undef DMibTemp_R0
#			undef DMibTemp_R1
#			undef DMibTemp_R2
#			undef DMibTemp_R3
#			undef DMibTemp_R4

			template <typename tf_CHashImpl>
			static void fs_GetDigest(const tf_CHashImpl &_Impl, typename tf_CHashImpl::CMessageDigest &_Digest)
			{
				tf_CHashImpl TempState(_Impl);

#ifdef DMibPLittleEndian
				static uint32 Pad[64/sizeof(uint32)] = {constant_uint64(0x00000080), 0};
#else
				static uint32 Pad[64/sizeof(uint32)] = {constant_uint64(0x80000000), 0};
#endif

				uint64 Size = fg_ByteSwapBE((TempState.m_nBytes % (constant_int64(0x1fffffffffffffff))) * 8);
				int Offset = (TempState.m_nBytes & 0x3f);

				TempState.f_AddData(Pad, (Offset < 56) ? (56 - Offset) : (120 - Offset));
				TempState.f_AddData(&Size, sizeof(Size));

				uint32 *pData = (uint32 *)_Digest.f_GetData();
				pData[0] = fg_ByteSwapBE(TempState.m_State.m_State[0]);
				pData[1] = fg_ByteSwapBE(TempState.m_State.m_State[1]);
				pData[2] = fg_ByteSwapBE(TempState.m_State.m_State[2]);
				pData[3] = fg_ByteSwapBE(TempState.m_State.m_State[3]);
				pData[4] = fg_ByteSwapBE(TempState.m_State.m_State[4]);
			}
		};


		class CHashImpl_SHA256
		{
			static const uint32 msp_K[64];
		public:

			typedef uint32 CData;

			enum
			{
				EBlockSize = 64/sizeof(CData),
				EDigestSize = 32
			};
			class CState
			{
			public:
				CData m_State[8];
			};
			static void fs_InitState(CState &_State)
			{
				_State.m_State[0] = 0x6a09e667;
				_State.m_State[1] = 0xbb67ae85;
				_State.m_State[2] = 0x3c6ef372;
				_State.m_State[3] = 0xa54ff53a;
				_State.m_State[4] = 0x510e527f;
				_State.m_State[5] = 0x9b05688c;
				_State.m_State[6] = 0x1f83d9ab;
				_State.m_State[7] = 0x5be0cd19;
			}

#			define DMibTemp_Block0(d_iData) (W[d_iData] = fg_ByteSwapBE(_pData[d_iData]))
#			define DMibTemp_Block2(d_iData) (W[d_iData&15]+=DMibTemp_Ss1(W[(d_iData-2)&15])+W[(d_iData-7)&15]+DMibTemp_Ss0(W[(d_iData-15)&15]))

#			define DMibTemp_Ch(d_X,d_Y,d_Z) (d_Z^(d_X&(d_Y^d_Z)))
#			define DMibTemp_Maj(d_X,d_Y,d_Z) ((d_X&d_Y)|(d_Z&(d_X|d_Y)))

#			define DMibTemp_A(d_iData) T[(0-d_iData)&7]
#			define DMibTemp_B(d_iData) T[(1-d_iData)&7]
#			define DMibTemp_C(d_iData) T[(2-d_iData)&7]
#			define DMibTemp_D(d_iData) T[(3-d_iData)&7]
#			define DMibTemp_E(d_iData) T[(4-d_iData)&7]
#			define DMibTemp_F(d_iData) T[(5-d_iData)&7]
#			define DMibTemp_G(d_iData) T[(6-d_iData)&7]
#			define DMibTemp_H(d_iData) T[(7-d_iData)&7]

#			define DMibTemp_R0(d_iData) DMibTemp_H(d_iData)+=DMibTemp_S1(DMibTemp_E(d_iData))+DMibTemp_Ch(DMibTemp_E(d_iData),DMibTemp_F(d_iData),DMibTemp_G(d_iData))+msp_K[d_iData]+(DMibTemp_Block0(d_iData));\
				DMibTemp_D(d_iData)+=DMibTemp_H(d_iData);DMibTemp_H(d_iData)+=DMibTemp_S0(DMibTemp_A(d_iData))+DMibTemp_Maj(DMibTemp_A(d_iData),DMibTemp_B(d_iData),DMibTemp_C(d_iData))

#			define DMibTemp_R1(d_iData) DMibTemp_H(d_iData)+=DMibTemp_S1(DMibTemp_E(d_iData))+DMibTemp_Ch(DMibTemp_E(d_iData),DMibTemp_F(d_iData),DMibTemp_G(d_iData))+msp_K[d_iData+j]+(DMibTemp_Block2(d_iData));\
				DMibTemp_D(d_iData)+=DMibTemp_H(d_iData);DMibTemp_H(d_iData)+=DMibTemp_S0(DMibTemp_A(d_iData))+DMibTemp_Maj(DMibTemp_A(d_iData),DMibTemp_B(d_iData),DMibTemp_C(d_iData))

			// for SHA256
#			define DMibTemp_S0(d_X) (fg_RotateRight(d_X,2)^fg_RotateRight(d_X,13)^fg_RotateRight(d_X,22))
#			define DMibTemp_S1(d_X) (fg_RotateRight(d_X,6)^fg_RotateRight(d_X,11)^fg_RotateRight(d_X,25))
#			define DMibTemp_Ss0(d_X) (fg_RotateRight(d_X,7)^fg_RotateRight(d_X,18)^(d_X>>3))
#			define DMibTemp_Ss1(d_X) (fg_RotateRight(d_X,17)^fg_RotateRight(d_X,19)^(d_X>>10))

			static void fs_Transform(CState &_State, const CData *_pData)
			{
				uint32 W[16];
				uint32 T[8];
				// Copy context->state[] to working vars
				T[0] = _State.m_State[0];
				T[1] = _State.m_State[1];
				T[2] = _State.m_State[2];
				T[3] = _State.m_State[3];
				T[4] = _State.m_State[4];
				T[5] = _State.m_State[5];
				T[6] = _State.m_State[6];
				T[7] = _State.m_State[7];
				// 64 operations, partially loop unrolled
				DMibTemp_R0( 0); DMibTemp_R0( 1); DMibTemp_R0( 2); DMibTemp_R0( 3);
				DMibTemp_R0( 4); DMibTemp_R0( 5); DMibTemp_R0( 6); DMibTemp_R0( 7);
				DMibTemp_R0( 8); DMibTemp_R0( 9); DMibTemp_R0(10); DMibTemp_R0(11);
				DMibTemp_R0(12); DMibTemp_R0(13); DMibTemp_R0(14); DMibTemp_R0(15);
				for (mint j=16; j<64; j+=16)
				{
					DMibTemp_R1( 0); DMibTemp_R1( 1); DMibTemp_R1( 2); DMibTemp_R1( 3);
					DMibTemp_R1( 4); DMibTemp_R1( 5); DMibTemp_R1( 6); DMibTemp_R1( 7);
					DMibTemp_R1( 8); DMibTemp_R1( 9); DMibTemp_R1(10); DMibTemp_R1(11);
					DMibTemp_R1(12); DMibTemp_R1(13); DMibTemp_R1(14); DMibTemp_R1(15);
				}
				/* Add the working vars back into context.state[] */
				W[0] = W[1] = W[3] = W[4] = W[5] = W[6] = W[7] = W[8] = W[9] = W[10] = W[11] = W[12] = W[13] = W[14] = W[15] = 0;
				_State.m_State[0] += DMibTemp_A(0);
				_State.m_State[1] += DMibTemp_B(0);
				_State.m_State[2] += DMibTemp_C(0);
				_State.m_State[3] += DMibTemp_D(0);
				_State.m_State[4] += DMibTemp_E(0);
				_State.m_State[5] += DMibTemp_F(0);
				_State.m_State[6] += DMibTemp_G(0);
				_State.m_State[7] += DMibTemp_H(0);
				/* Wipe variables */
				T[0] = T[1] = T[3] = T[4] = T[5] = T[6] = T[7] = 0;
			}

#			undef DMibTemp_Block0
#			undef DMibTemp_Block2
#			undef DMibTemp_Ch
#			undef DMibTemp_Maj
#			undef DMibTemp_A
#			undef DMibTemp_B
#			undef DMibTemp_C
#			undef DMibTemp_D
#			undef DMibTemp_E
#			undef DMibTemp_F
#			undef DMibTemp_G
#			undef DMibTemp_H
#			undef DMibTemp_R
#			undef DMibTemp_S0
#			undef DMibTemp_S1
#			undef DMibTemp_Ss0
#			undef DMibTemp_Ss1

			template <typename tf_CHashImpl>
			static void fs_GetDigest(const tf_CHashImpl &_Impl, typename tf_CHashImpl::CMessageDigest &_Digest)
			{
				tf_CHashImpl TempState(_Impl);

#ifdef DMibPLittleEndian
				static uint32 Pad[64/sizeof(uint32)] = {constant_uint64(0x00000080), 0};
#else
				static uint32 Pad[64/sizeof(uint32)] = {constant_uint64(0x80000000), 0};
#endif

				uint64 Size = fg_ByteSwapBE((TempState.m_nBytes % (constant_int64(0x1fffffffffffffff))) * 8);
				int Offset = (TempState.m_nBytes & 0x3f);

				TempState.f_AddData(Pad, (Offset < 56) ? (56 - Offset) : (120 - Offset));
				TempState.f_AddData(&Size, sizeof(Size));

				uint32 *pData = (uint32 *)_Digest.f_GetData();
				pData[0] = fg_ByteSwapBE(TempState.m_State.m_State[0]);
				pData[1] = fg_ByteSwapBE(TempState.m_State.m_State[1]);
				pData[2] = fg_ByteSwapBE(TempState.m_State.m_State[2]);
				pData[3] = fg_ByteSwapBE(TempState.m_State.m_State[3]);
				pData[4] = fg_ByteSwapBE(TempState.m_State.m_State[4]);
				pData[5] = fg_ByteSwapBE(TempState.m_State.m_State[5]);
				pData[6] = fg_ByteSwapBE(TempState.m_State.m_State[6]);
				pData[7] = fg_ByteSwapBE(TempState.m_State.m_State[7]);
			}
		};


		class CHashImpl_SHA512
		{
			static const uint64 msp_K[80];
		public:

			typedef uint64 CData;

			enum
			{
				EBlockSize = 128/sizeof(CData),
				EDigestSize = 64
			};
			class CState
			{
			public:
				CData m_State[8];
			};
			static void fs_InitState(CState &_State)
			{
				_State.m_State[0] = constant_uint64(0x6a09e667f3bcc908);
				_State.m_State[1] = constant_uint64(0xbb67ae8584caa73b);
				_State.m_State[2] = constant_uint64(0x3c6ef372fe94f82b);
				_State.m_State[3] = constant_uint64(0xa54ff53a5f1d36f1);
				_State.m_State[4] = constant_uint64(0x510e527fade682d1);
				_State.m_State[5] = constant_uint64(0x9b05688c2b3e6c1f);
				_State.m_State[6] = constant_uint64(0x1f83d9abfb41bd6b);
				_State.m_State[7] = constant_uint64(0x5be0cd19137e2179);
			}

#			define DMibTemp_Block0(d_iData) (W[d_iData] = fg_ByteSwapBE(_pData[d_iData]))
#			define DMibTemp_Block2(d_iData) (W[d_iData&15]+=DMibTemp_Ss1(W[(d_iData-2)&15])+W[(d_iData-7)&15]+DMibTemp_Ss0(W[(d_iData-15)&15]))

#			define DMibTemp_Ch(d_X,d_Y,d_Z) (d_Z^(d_X&(d_Y^d_Z)))
#			define DMibTemp_Maj(d_X,d_Y,d_Z) ((d_X&d_Y)|(d_Z&(d_X|d_Y)))

#			define DMibTemp_A(d_iData) T[(0-d_iData)&7]
#			define DMibTemp_B(d_iData) T[(1-d_iData)&7]
#			define DMibTemp_C(d_iData) T[(2-d_iData)&7]
#			define DMibTemp_D(d_iData) T[(3-d_iData)&7]
#			define DMibTemp_E(d_iData) T[(4-d_iData)&7]
#			define DMibTemp_F(d_iData) T[(5-d_iData)&7]
#			define DMibTemp_G(d_iData) T[(6-d_iData)&7]
#			define DMibTemp_H(d_iData) T[(7-d_iData)&7]

#			define DMibTemp_R0(d_iData) DMibTemp_H(d_iData)+=DMibTemp_S1(DMibTemp_E(d_iData))+DMibTemp_Ch(DMibTemp_E(d_iData),DMibTemp_F(d_iData),DMibTemp_G(d_iData))+msp_K[d_iData]+(DMibTemp_Block0(d_iData));\
				DMibTemp_D(d_iData)+=DMibTemp_H(d_iData);DMibTemp_H(d_iData)+=DMibTemp_S0(DMibTemp_A(d_iData))+DMibTemp_Maj(DMibTemp_A(d_iData),DMibTemp_B(d_iData),DMibTemp_C(d_iData))

#			define DMibTemp_R1(d_iData) DMibTemp_H(d_iData)+=DMibTemp_S1(DMibTemp_E(d_iData))+DMibTemp_Ch(DMibTemp_E(d_iData),DMibTemp_F(d_iData),DMibTemp_G(d_iData))+msp_K[d_iData+j]+(DMibTemp_Block2(d_iData));\
				DMibTemp_D(d_iData)+=DMibTemp_H(d_iData);DMibTemp_H(d_iData)+=DMibTemp_S0(DMibTemp_A(d_iData))+DMibTemp_Maj(DMibTemp_A(d_iData),DMibTemp_B(d_iData),DMibTemp_C(d_iData))

			#define DMibTemp_S0(d_X) (fg_RotateRight(d_X,28)^fg_RotateRight(d_X,34)^fg_RotateRight(d_X,39))
			#define DMibTemp_S1(d_X) (fg_RotateRight(d_X,14)^fg_RotateRight(d_X,18)^fg_RotateRight(d_X,41))
			#define DMibTemp_Ss0(d_X) (fg_RotateRight(d_X,1)^fg_RotateRight(d_X,8)^(d_X>>7))
			#define DMibTemp_Ss1(d_X) (fg_RotateRight(d_X,19)^fg_RotateRight(d_X,61)^(d_X>>6))

			static void fs_Transform(CState &_State, const CData *_pData)
			{
				uint64 W[16];
				uint64 T[8];

				/* Copy context->state[] to working vars */
				T[0] = _State.m_State[0];
				T[1] = _State.m_State[1];
				T[2] = _State.m_State[2];
				T[3] = _State.m_State[3];
				T[4] = _State.m_State[4];
				T[5] = _State.m_State[5];
				T[6] = _State.m_State[6];
				T[7] = _State.m_State[7];
				DMibTemp_R0( 0); DMibTemp_R0( 1); DMibTemp_R0( 2); DMibTemp_R0( 3);
				DMibTemp_R0( 4); DMibTemp_R0( 5); DMibTemp_R0( 6); DMibTemp_R0( 7);
				DMibTemp_R0( 8); DMibTemp_R0( 9); DMibTemp_R0(10); DMibTemp_R0(11);
				DMibTemp_R0(12); DMibTemp_R0(13); DMibTemp_R0(14); DMibTemp_R0(15);
				/* 80 operations, partially loop unrolled */
				for (mint j=16; j<80; j+=16)
				{
					DMibTemp_R1( 0); DMibTemp_R1( 1); DMibTemp_R1( 2); DMibTemp_R1( 3);
					DMibTemp_R1( 4); DMibTemp_R1( 5); DMibTemp_R1( 6); DMibTemp_R1( 7);
					DMibTemp_R1( 8); DMibTemp_R1( 9); DMibTemp_R1(10); DMibTemp_R1(11);
					DMibTemp_R1(12); DMibTemp_R1(13); DMibTemp_R1(14); DMibTemp_R1(15);
				}
				/* Add the working vars back into context.state[] */
				W[0] = W[1] = W[3] = W[4] = W[5] = W[6] = W[7] = W[8] = W[9] = W[10] = W[11] = W[12] = W[13] = W[14] = W[15] = 0;
				_State.m_State[0] += DMibTemp_A(0);
				_State.m_State[1] += DMibTemp_B(0);
				_State.m_State[2] += DMibTemp_C(0);
				_State.m_State[3] += DMibTemp_D(0);
				_State.m_State[4] += DMibTemp_E(0);
				_State.m_State[5] += DMibTemp_F(0);
				_State.m_State[6] += DMibTemp_G(0);
				_State.m_State[7] += DMibTemp_H(0);
				/* Wipe variables */
				T[0] = T[1] = T[3] = T[4] = T[5] = T[6] = T[7] = 0;
			}

#			undef DMibTemp_Block0
#			undef DMibTemp_Block2
#			undef DMibTemp_Ch
#			undef DMibTemp_Maj
#			undef DMibTemp_A
#			undef DMibTemp_B
#			undef DMibTemp_C
#			undef DMibTemp_D
#			undef DMibTemp_E
#			undef DMibTemp_F
#			undef DMibTemp_G
#			undef DMibTemp_H
#			undef DMibTemp_R0
#			undef DMibTemp_R1
#			undef DMibTemp_S0
#			undef DMibTemp_S1
#			undef DMibTemp_Ss0
#			undef DMibTemp_Ss1

			template <typename tf_CHashImpl>
			static void fs_GetDigest(const tf_CHashImpl &_Impl, typename tf_CHashImpl::CMessageDigest &_Digest)
			{
				tf_CHashImpl TempState(_Impl);

#ifdef DMibPLittleEndian
				static uint64 Pad[128/sizeof(uint64)] = {constant_uint64(0x0000000000000080), 0};
#else
				static uint64 Pad[128/sizeof(uint64)] = {constant_uint64(0x8000000000000000), 0};
#endif

				uint64 Size = fg_ByteSwapBE((TempState.m_nBytes % (constant_int64(0x1fffffffffffffff))) * 8);
				int Offset = (TempState.m_nBytes & 0x7f);
				uint64 Size0 = 0;

				TempState.f_AddData(Pad, (Offset < 112) ? (112 - Offset) : (240 - Offset));
				TempState.f_AddData(&Size0, sizeof(Size0));
				TempState.f_AddData(&Size, sizeof(Size));

				uint64 *pData = (uint64 *)_Digest.f_GetData();
				pData[0] = fg_ByteSwapBE(TempState.m_State.m_State[0]);
				pData[1] = fg_ByteSwapBE(TempState.m_State.m_State[1]);
				pData[2] = fg_ByteSwapBE(TempState.m_State.m_State[2]);
				pData[3] = fg_ByteSwapBE(TempState.m_State.m_State[3]);
				pData[4] = fg_ByteSwapBE(TempState.m_State.m_State[4]);
				pData[5] = fg_ByteSwapBE(TempState.m_State.m_State[5]);
				pData[6] = fg_ByteSwapBE(TempState.m_State.m_State[6]);
				pData[7] = fg_ByteSwapBE(TempState.m_State.m_State[7]);
			}
		};

		class CHashImpl_SHA384 : public CHashImpl_SHA512
		{
		public:

			enum
			{
				EBlockSize = 128/sizeof(CData),
				EDigestSize = 48
			};
			static void fs_InitState(CState &_State)
			{
				_State.m_State[0] = constant_uint64(0xcbbb9d5dc1059ed8);
				_State.m_State[1] = constant_uint64(0x629a292a367cd507);
				_State.m_State[2] = constant_uint64(0x9159015a3070dd17);
				_State.m_State[3] = constant_uint64(0x152fecd8f70e5939);
				_State.m_State[4] = constant_uint64(0x67332667ffc00b31);
				_State.m_State[5] = constant_uint64(0x8eb44a8768581511);
				_State.m_State[6] = constant_uint64(0xdb0c2e0d64f98fa7);
				_State.m_State[7] = constant_uint64(0x47b5481dbefa4fa4);
			}

			template <typename tf_CHashImpl>
			static void fs_GetDigest(const tf_CHashImpl &_Impl, typename tf_CHashImpl::CMessageDigest &_Digest)
			{
				tf_CHashImpl TempState(_Impl);

#ifdef DMibPLittleEndian
				static uint64 Pad[128/sizeof(uint64)] = {constant_uint64(0x0000000000000080), 0};
#else
				static uint64 Pad[128/sizeof(uint64)] = {constant_uint64(0x8000000000000000), 0};
#endif

				uint64 Size = fg_ByteSwapBE((TempState.m_nBytes % (constant_int64(0x1fffffffffffffff))) * 8);
				int Offset = (TempState.m_nBytes & 0x7f);
				uint64 Size0 = 0;

				TempState.f_AddData(Pad, (Offset < 112) ? (112 - Offset) : (240 - Offset));
				TempState.f_AddData(&Size0, sizeof(Size0));
				TempState.f_AddData(&Size, sizeof(Size));

				uint64 *pData = (uint64 *)_Digest.f_GetData();
				pData[0] = fg_ByteSwapBE(TempState.m_State.m_State[0]);
				pData[1] = fg_ByteSwapBE(TempState.m_State.m_State[1]);
				pData[2] = fg_ByteSwapBE(TempState.m_State.m_State[2]);
				pData[3] = fg_ByteSwapBE(TempState.m_State.m_State[3]);
				pData[4] = fg_ByteSwapBE(TempState.m_State.m_State[4]);
				pData[5] = fg_ByteSwapBE(TempState.m_State.m_State[5]);
			}
		};

		typedef TCHashImpl<CHashImpl_SHA1> CHash_SHA1;
		typedef CHash_SHA1::CMessageDigest CHashDigest_SHA1;

		typedef TCHashImpl<CHashImpl_SHA256> CHash_SHA256;
		typedef CHash_SHA256::CMessageDigest CHashDigest_SHA256;

		typedef TCHashImpl<CHashImpl_SHA512> CHash_SHA512;
		typedef CHash_SHA512::CMessageDigest CHashDigest_SHA512;

		typedef TCHashImpl<CHashImpl_SHA384> CHash_SHA384;
		typedef CHash_SHA384::CMessageDigest CHashDigest_SHA384;

	}
}

