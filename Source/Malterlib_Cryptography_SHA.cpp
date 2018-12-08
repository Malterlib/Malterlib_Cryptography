// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include "Malterlib_Cryptography_SHA.h"

namespace NMib::NCryptography
{
	const uint32 CHashImpl_SHA256::msp_K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	const uint64 CHashImpl_SHA512::msp_K[80] = {
		constant_uint64(0x428a2f98d728ae22), constant_uint64(0x7137449123ef65cd),
		constant_uint64(0xb5c0fbcfec4d3b2f), constant_uint64(0xe9b5dba58189dbbc),
		constant_uint64(0x3956c25bf348b538), constant_uint64(0x59f111f1b605d019),
		constant_uint64(0x923f82a4af194f9b), constant_uint64(0xab1c5ed5da6d8118),
		constant_uint64(0xd807aa98a3030242), constant_uint64(0x12835b0145706fbe),
		constant_uint64(0x243185be4ee4b28c), constant_uint64(0x550c7dc3d5ffb4e2),
		constant_uint64(0x72be5d74f27b896f), constant_uint64(0x80deb1fe3b1696b1),
		constant_uint64(0x9bdc06a725c71235), constant_uint64(0xc19bf174cf692694),
		constant_uint64(0xe49b69c19ef14ad2), constant_uint64(0xefbe4786384f25e3),
		constant_uint64(0x0fc19dc68b8cd5b5), constant_uint64(0x240ca1cc77ac9c65),
		constant_uint64(0x2de92c6f592b0275), constant_uint64(0x4a7484aa6ea6e483),
		constant_uint64(0x5cb0a9dcbd41fbd4), constant_uint64(0x76f988da831153b5),
		constant_uint64(0x983e5152ee66dfab), constant_uint64(0xa831c66d2db43210),
		constant_uint64(0xb00327c898fb213f), constant_uint64(0xbf597fc7beef0ee4),
		constant_uint64(0xc6e00bf33da88fc2), constant_uint64(0xd5a79147930aa725),
		constant_uint64(0x06ca6351e003826f), constant_uint64(0x142929670a0e6e70),
		constant_uint64(0x27b70a8546d22ffc), constant_uint64(0x2e1b21385c26c926),
		constant_uint64(0x4d2c6dfc5ac42aed), constant_uint64(0x53380d139d95b3df),
		constant_uint64(0x650a73548baf63de), constant_uint64(0x766a0abb3c77b2a8),
		constant_uint64(0x81c2c92e47edaee6), constant_uint64(0x92722c851482353b),
		constant_uint64(0xa2bfe8a14cf10364), constant_uint64(0xa81a664bbc423001),
		constant_uint64(0xc24b8b70d0f89791), constant_uint64(0xc76c51a30654be30),
		constant_uint64(0xd192e819d6ef5218), constant_uint64(0xd69906245565a910),
		constant_uint64(0xf40e35855771202a), constant_uint64(0x106aa07032bbd1b8),
		constant_uint64(0x19a4c116b8d2d0c8), constant_uint64(0x1e376c085141ab53),
		constant_uint64(0x2748774cdf8eeb99), constant_uint64(0x34b0bcb5e19b48a8),
		constant_uint64(0x391c0cb3c5c95a63), constant_uint64(0x4ed8aa4ae3418acb),
		constant_uint64(0x5b9cca4f7763e373), constant_uint64(0x682e6ff3d6b2b8a3),
		constant_uint64(0x748f82ee5defb2fc), constant_uint64(0x78a5636f43172f60),
		constant_uint64(0x84c87814a1f0ab72), constant_uint64(0x8cc702081a6439ec),
		constant_uint64(0x90befffa23631e28), constant_uint64(0xa4506cebde82bde9),
		constant_uint64(0xbef9a3f7b2c67915), constant_uint64(0xc67178f2e372532b),
		constant_uint64(0xca273eceea26619c), constant_uint64(0xd186b8c721c0c207),
		constant_uint64(0xeada7dd6cde0eb1e), constant_uint64(0xf57d4f7fee6ed178),
		constant_uint64(0x06f067aa72176fba), constant_uint64(0x0a637dc5a2c898a6),
		constant_uint64(0x113f9804bef90dae), constant_uint64(0x1b710b35131c471b),
		constant_uint64(0x28db77f523047d84), constant_uint64(0x32caab7b40c72493),
		constant_uint64(0x3c9ebe0a15c9bebc), constant_uint64(0x431d67c49c100d4c),
		constant_uint64(0x4cc5d4becb3e42b6), constant_uint64(0x597f299cfc657e2a),
		constant_uint64(0x5fcb6fab3ad6faec), constant_uint64(0x6c44198c4a475817)
	};
}
