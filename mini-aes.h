/*
 * a simple mini-AES implementation
 * by: Muhammad Reza bin Z'aba,
 * Cryptography Lab, MIMOS Berhad
 *
 * 11 Oct 2012
 * -----------
 * - Only supports 16-bit block and key using a 2x2 matrix
 *
 * 11 Oct 2017
 * -----------
 * - Expanding the 16-bit block Mini-AES to support key sizes of
 *   16, 24 and 32 bits
 *
 */

#include "common.h"
#define ENC 0
#define DEC 1
#define R 10 // specifies number of rounds

void keySchedule64(u64 masterkey, u64 *key);
u64 subkeyComputeBackward(u64 k, u8 r);
u64 subkeyComputeForward(u64 k, u8 r);
void sbox4x4_8bit_Construct();
u64 NibbleSub64(u64 x);
u64 NibbleSub64Inv(u64 x);
u64 ROT64L(u64 a, u8 n);
u64 ShiftRow64(u64 x);
u64 ShiftRow64Inv(u64 x);
u64 MixColumn64(u64 x);
u64 MixColumn64Inv(u64 x);
void MixColumn64_Table_Construct();
u8 MixColumn64_Nibble1(u16 x);
u8 MixColumn64_Nibble2(u16 x);
u8 MixColumn64_Nibble3(u16 x);
u8 MixColumn64_Nibble4(u16 x);
u8 MixColumn64_Nibble1Inv(u16 x);
u8 MixColumn64_Nibble2Inv(u16 x);
u8 MixColumn64_Nibble3Inv(u16 x);
u8 MixColumn64_Nibble4Inv(u16 x);
u64 oneRoundEnc64(u64 x, u64 k);
u64 lastRoundEnc64(u64 x, u64 k);
u64 oneRoundDec64(u64 x, u64 k);
u64 firstRoundDec64(u64 x, u64 k);
u64 encrypt64(u64 x, u64 *key);
u64 decrypt64(u64 x, u64 *key);

void keySchedule(u32 masterkey, u16 *key, u8 keylen, u8 *Nr);
u16 NibbleSub(u16 x);
u16 NibbleSubInv(u16 x);
u16 ShiftRow(u16 x);
u16 MixColumn(u16 x);
void MixColumn_Table_Construct();
u8 MixColumn_Nibble1(u8 x);
u8 MixColumn_Nibble2(u8 x);
u16 oneRoundEnc(u16 x, u16 k);
u16 oneRoundEnc_print(u16 x, u16 k);
u16 encrypt(u16 x, u16 *key, u8 Nr);
u16 encrypt_print(u16 x, u16 *key, u8 Nr);
u16 oneRoundDec(u16 x, u16 k);
u16 decrypt(u16 x, u16 *key, u8 Nr) ;
