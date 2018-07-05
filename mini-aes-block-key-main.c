/*
 * mini-aes-main.c
 *
 *  Created on: Oct 9, 2012
 *      Author: mrz
 */

#include "common.h"
#include "mini-aes.h"
#include <time.h>
#include <math.h>

// to obtain system information
// refer http://c-program-example.com/2012/01/c-program-to-get-the-system-information.html
#include<sys/utsname.h>   /* Header for 'uname'  */

void print_n_choose_2();
void check_for_same_key();
void check_for_same_key_fix_key();
void same_key_analysis(u16 c, u16 *key, u8 Nr);
void analyze_mini_aes_key_sch();
void analyze_mini_aes_a();
void print_latex_x_xor_sx();
void print_latex_x_xor_2sx();
void print_latex_x_xor_3sx();
void print_x_xor_sx_preimage(u8 x);
void analysis_x_xor_sx();
void analysis_x_xor_2sx();
void analysis_x_xor_3sx();
void solve_key_eqns(u8 w0);
void build_mult_by_x_table(u8 x);
void timestamp (void);

// aes s-box
u8 aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
	0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
	0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
	0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

u8 aes_sbox_inv[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
	0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44,
	0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
	0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
	0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc,
	0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57,
	0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
	0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03,
	0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce,
	0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
	0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e,
	0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe,
	0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
	0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
	0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c,
	0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
	0x55, 0x21, 0x0c, 0x7d
};

u8 aes_multby2[256] = {
	0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E,
	0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
	0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E,
	0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E,
	0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E,
	0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE, 0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE,
	0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE, 0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE,
	0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE, 0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE,
	0x1B, 0x19, 0x1F, 0x1D, 0x13, 0x11, 0x17, 0x15, 0x0B, 0x09, 0x0F, 0x0D, 0x03, 0x01, 0x07, 0x05,
	0x3B, 0x39, 0x3F, 0x3D, 0x33, 0x31, 0x37, 0x35, 0x2B, 0x29, 0x2F, 0x2D, 0x23, 0x21, 0x27, 0x25,
	0x5B, 0x59, 0x5F, 0x5D, 0x53, 0x51, 0x57, 0x55, 0x4B, 0x49, 0x4F, 0x4D, 0x43, 0x41, 0x47, 0x45,
	0x7B, 0x79, 0x7F, 0x7D, 0x73, 0x71, 0x77, 0x75, 0x6B, 0x69, 0x6F, 0x6D, 0x63, 0x61, 0x67, 0x65,
	0x9B, 0x99, 0x9F, 0x9D, 0x93, 0x91, 0x97, 0x95, 0x8B, 0x89, 0x8F, 0x8D, 0x83, 0x81, 0x87, 0x85,
	0xBB, 0xB9, 0xBF, 0xBD, 0xB3, 0xB1, 0xB7, 0xB5, 0xAB, 0xA9, 0xAF, 0xAD, 0xA3, 0xA1, 0xA7, 0xA5,
	0xDB, 0xD9, 0xDF, 0xDD, 0xD3, 0xD1, 0xD7, 0xD5, 0xCB, 0xC9, 0xCF, 0xCD, 0xC3, 0xC1, 0xC7, 0xC5,
	0xFB, 0xF9, 0xFF, 0xFD, 0xF3, 0xF1, 0xF7, 0xF5, 0xEB, 0xE9, 0xEF, 0xED, 0xE3, 0xE1, 0xE7, 0xE5
};

u8 aes_multby3[256] = {
	0x00, 0x03, 0x06, 0x05, 0x0C, 0x0F, 0x0A, 0x09, 0x18, 0x1B, 0x1E, 0x1D, 0x14, 0x17, 0x12, 0x11,
	0x30, 0x33, 0x36, 0x35, 0x3C, 0x3F, 0x3A, 0x39, 0x28, 0x2B, 0x2E, 0x2D, 0x24, 0x27, 0x22, 0x21,
	0x60, 0x63, 0x66, 0x65, 0x6C, 0x6F, 0x6A, 0x69, 0x78, 0x7B, 0x7E, 0x7D, 0x74, 0x77, 0x72, 0x71,
	0x50, 0x53, 0x56, 0x55, 0x5C, 0x5F, 0x5A, 0x59, 0x48, 0x4B, 0x4E, 0x4D, 0x44, 0x47, 0x42, 0x41,
	0xC0, 0xC3, 0xC6, 0xC5, 0xCC, 0xCF, 0xCA, 0xC9, 0xD8, 0xDB, 0xDE, 0xDD, 0xD4, 0xD7, 0xD2, 0xD1,
	0xF0, 0xF3, 0xF6, 0xF5, 0xFC, 0xFF, 0xFA, 0xF9, 0xE8, 0xEB, 0xEE, 0xED, 0xE4, 0xE7, 0xE2, 0xE1,
	0xA0, 0xA3, 0xA6, 0xA5, 0xAC, 0xAF, 0xAA, 0xA9, 0xB8, 0xBB, 0xBE, 0xBD, 0xB4, 0xB7, 0xB2, 0xB1,
	0x90, 0x93, 0x96, 0x95, 0x9C, 0x9F, 0x9A, 0x99, 0x88, 0x8B, 0x8E, 0x8D, 0x84, 0x87, 0x82, 0x81,
	0x9B, 0x98, 0x9D, 0x9E, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8F, 0x8C, 0x89, 0x8A,
	0xAB, 0xA8, 0xAD, 0xAE, 0xA7, 0xA4, 0xA1, 0xA2, 0xB3, 0xB0, 0xB5, 0xB6, 0xBF, 0xBC, 0xB9, 0xBA,
	0xFB, 0xF8, 0xFD, 0xFE, 0xF7, 0xF4, 0xF1, 0xF2, 0xE3, 0xE0, 0xE5, 0xE6, 0xEF, 0xEC, 0xE9, 0xEA,
	0xCB, 0xC8, 0xCD, 0xCE, 0xC7, 0xC4, 0xC1, 0xC2, 0xD3, 0xD0, 0xD5, 0xD6, 0xDF, 0xDC, 0xD9, 0xDA,
	0x5B, 0x58, 0x5D, 0x5E, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4F, 0x4C, 0x49, 0x4A,
	0x6B, 0x68, 0x6D, 0x6E, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7F, 0x7C, 0x79, 0x7A,
	0x3B, 0x38, 0x3D, 0x3E, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2F, 0x2C, 0x29, 0x2A,
	0x0B, 0x08, 0x0D, 0x0E, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1F, 0x1C, 0x19, 0x1A
};

// X XOR S(X) table for AES
u8 x_xor_sx_table[256] = {
	0x63, 0x7D, 0x75, 0x78, 0xF6, 0x6E, 0x69, 0xC2,
	0x38, 0x08, 0x6D, 0x20, 0xF2, 0xDA, 0xA5, 0x79,
	0xDA, 0x93, 0xDB, 0x6E, 0xEE, 0x4C, 0x51, 0xE7,
	0xB5, 0xCD, 0xB8, 0xB4, 0x80, 0xB9, 0x6C, 0xDF,
	0x97, 0xDC, 0xB1, 0x05, 0x12, 0x1A, 0xD1, 0xEB,
	0x1C, 0x8C, 0xCF, 0xDA, 0x5D, 0xF5, 0x1F, 0x3A,
	0x34, 0xF6, 0x11, 0xF0, 0x2C, 0xA3, 0x33, 0xAD,
	0x3F, 0x2B, 0xBA, 0xD9, 0xD7, 0x1A, 0x8C, 0x4A,
	0x49, 0xC2, 0x6E, 0x59, 0x5F, 0x2B, 0x1C, 0xE7,
	0x1A, 0x72, 0x9C, 0xF8, 0x65, 0xAE, 0x61, 0xCB,
	0x03, 0x80, 0x52, 0xBE, 0x74, 0xA9, 0xE7, 0x0C,
	0x32, 0x92, 0xE4, 0x62, 0x16, 0x11, 0x06, 0x90,
	0xB0, 0x8E, 0xC8, 0x98, 0x27, 0x28, 0x55, 0xE2,
	0x2D, 0x90, 0x68, 0x14, 0x3C, 0x51, 0xF1, 0xC7,
	0x21, 0xD2, 0x32, 0xFC, 0xE6, 0xE8, 0x4E, 0x82,
	0xC4, 0xCF, 0xA0, 0x5A, 0x6C, 0x82, 0x8D, 0xAD,
	0x4D, 0x8D, 0x91, 0x6F, 0xDB, 0x12, 0xC2, 0x90,
	0x4C, 0x2E, 0xF4, 0xB6, 0xE8, 0xD0, 0x97, 0xFC,
	0xF0, 0x10, 0xDD, 0x4F, 0xB6, 0xBF, 0x06, 0x1F,
	0xDE, 0x77, 0x22, 0x8F, 0x42, 0xC3, 0x95, 0x44,
	0x40, 0x93, 0x98, 0xA9, 0xED, 0xA3, 0x82, 0xFB,
	0x6A, 0x7A, 0x06, 0xC9, 0x3D, 0x38, 0x4A, 0xD6,
	0x57, 0x79, 0x85, 0xDE, 0x39, 0x60, 0xF8, 0x1E,
	0xD4, 0xEF, 0x4E, 0x51, 0xD9, 0xC7, 0x10, 0xB7,
	0x7A, 0xB9, 0xE7, 0xED, 0xD8, 0x63, 0x72, 0x01,
	0x20, 0x14, 0xBE, 0xD4, 0x87, 0x70, 0x45, 0x45,
	0xA0, 0xEF, 0x67, 0xB5, 0x9C, 0xD6, 0x20, 0xD9,
	0xB9, 0xEC, 0x8D, 0x62, 0x5A, 0x1C, 0xC3, 0x41,
	0x01, 0x19, 0x7A, 0xF2, 0x8D, 0x3C, 0x68, 0x73,
	0x73, 0xF7, 0x6D, 0x02, 0x22, 0xB8, 0xC6, 0x30,
	0x7C, 0x50, 0x7B, 0xFE, 0x4B, 0x13, 0xB4, 0x9F,
	0xB9, 0x60, 0xD7, 0xF4, 0x4C, 0xA9, 0x45, 0xE9
};

// X XOR 2S(X) table for AES
u8 x_xor_2sx_table[256] = {
	0xC6, 0xF9, 0xEC, 0xF5, 0xFB, 0xD3, 0xD8, 0x96,
	0x68, 0x0B, 0xC4, 0x5D, 0xEB, 0xB8, 0x43, 0xE3,
	0x9F, 0x0E, 0x9B, 0xE9, 0xFB, 0xA7, 0x98, 0xEC,
	0x59, 0xAA, 0x45, 0x5E, 0x3F, 0x4E, 0xFA, 0x84,
	0x55, 0xC0, 0x1F, 0x6F, 0x48, 0x5B, 0xD3, 0xA4,
	0x40, 0x78, 0xFB, 0xD2, 0xCE, 0x86, 0x4C, 0x05,
	0x38, 0xA4, 0x74, 0xAE, 0x04, 0x02, 0x3C, 0x18,
	0x36, 0x1D, 0x21, 0xE4, 0xF1, 0x73, 0x41, 0xD5,
	0x52, 0x5C, 0x1A, 0x77, 0x72, 0x99, 0xF2, 0x1C,
	0xEC, 0x3F, 0xFD, 0x36, 0x1E, 0x90, 0x10, 0x5C,
	0xF6, 0xE8, 0x52, 0x92, 0x14, 0xB6, 0x2F, 0xE1,
	0x8C, 0xD4, 0x3D, 0x29, 0xC8, 0xC5, 0xEE, 0xDA,
	0xDB, 0xA4, 0x2D, 0x8E, 0xE2, 0xFF, 0x00, 0x76,
	0xE2, 0x80, 0x6E, 0x95, 0xCC, 0x15, 0x4B, 0x24,
	0xD2, 0x2C, 0xF2, 0x76, 0x4B, 0x54, 0x06, 0x86,
	0x1B, 0x0E, 0xD5, 0x39, 0x5C, 0x98, 0x83, 0xC0,
	0x01, 0x99, 0xA4, 0x40, 0x3A, 0xB0, 0x0E, 0xA9,
	0x1B, 0xDC, 0x76, 0xF1, 0x44, 0x37, 0xBC, 0x69,
	0x50, 0x88, 0x0C, 0x30, 0xD0, 0xC1, 0xAD, 0x9C,
	0x14, 0x5E, 0xF1, 0xB3, 0x3B, 0x21, 0x88, 0x32,
	0x7B, 0xC5, 0xD6, 0xB7, 0x36, 0xA9, 0xEE, 0x1F,
	0x37, 0x14, 0xE9, 0x6F, 0x95, 0x9C, 0x7D, 0x5D,
	0x65, 0x3A, 0xDC, 0x69, 0xB5, 0x04, 0x2A, 0xFE,
	0x60, 0x15, 0x49, 0x74, 0x76, 0x49, 0xF9, 0xAF,
	0xAF, 0x31, 0x88, 0x9F, 0xFC, 0x92, 0xB5, 0x50,
	0x03, 0x68, 0x22, 0xF5, 0x5A, 0xAC, 0xC3, 0xC0,
	0x30, 0xAD, 0xA3, 0x1F, 0x44, 0xD3, 0x21, 0xCB,
	0x1A, 0xB3, 0x74, 0xB2, 0xCB, 0x44, 0xE4, 0xF8,
	0x39, 0x0A, 0xC9, 0xC1, 0x36, 0x4C, 0xE1, 0xD4,
	0xC5, 0xD5, 0xFF, 0x22, 0x6B, 0x47, 0xBE, 0x4A,
	0xF3, 0xA8, 0xFB, 0xE9, 0x91, 0x22, 0x72, 0x27,
	0x7A, 0xD0, 0xA0, 0xE5, 0x87, 0x55, 0x93, 0xD3
};

// X XOR 3S(X) table for AES
u8 x_xor_3sx_table[256] = {
	0xA5, 0x85, 0x9B, 0x8E, 0x09, 0xB8, 0xB7, 0x53,
	0x58, 0x0A, 0xA3, 0x76, 0x15, 0x6F, 0xE8, 0x95,
	0x55, 0x8C, 0x52, 0x94, 0x01, 0xFE, 0xDF, 0x1C,
	0xF4, 0x7E, 0xE7, 0xF1, 0xA3, 0xEA, 0x88, 0x44,
	0xE2, 0x3D, 0x8C, 0x49, 0x7E, 0x64, 0x24, 0x68,
	0x74, 0xDD, 0x1E, 0x23, 0xBF, 0x5E, 0x7D, 0x10,
	0x3C, 0x63, 0x57, 0x6D, 0x1C, 0x94, 0x39, 0x82,
	0x31, 0x0F, 0xA1, 0x06, 0x1A, 0x54, 0xF3, 0xA0,
	0x5B, 0xDF, 0x36, 0x6D, 0x69, 0xF7, 0xA8, 0xBC,
	0xBE, 0x04, 0x2B, 0x85, 0x37, 0x73, 0x3F, 0xD8,
	0xA5, 0x39, 0x52, 0x7F, 0x34, 0x4A, 0x9E, 0xBA,
	0xE6, 0x1F, 0x83, 0x10, 0x82, 0x89, 0xB6, 0x15,
	0x0B, 0x4B, 0x87, 0x75, 0xA1, 0xB2, 0x33, 0xF3,
	0xA7, 0x79, 0x6C, 0xEA, 0x9C, 0x29, 0xD4, 0x8C,
	0x83, 0x8F, 0xB2, 0xF9, 0xD9, 0xC9, 0x3E, 0x73,
	0xA7, 0xB8, 0x0F, 0x18, 0x4C, 0x67, 0x70, 0x12,
	0xCC, 0x95, 0xB7, 0xAC, 0x65, 0x27, 0x4A, 0xBE,
	0xDF, 0x7B, 0x08, 0xCC, 0x20, 0x6A, 0xA5, 0x1A,
	0x30, 0x09, 0x43, 0xEC, 0xF2, 0xEB, 0x3D, 0x14,
	0x52, 0xB0, 0x49, 0xA7, 0xE5, 0x7F, 0x83, 0xE9,
	0x9B, 0xF7, 0xEC, 0xBD, 0x7F, 0xAF, 0xCA, 0x43,
	0xF5, 0xC7, 0x45, 0x0D, 0x04, 0x09, 0x99, 0x24,
	0x82, 0xF2, 0xEB, 0x04, 0x38, 0xD1, 0x64, 0x57,
	0x0C, 0x43, 0xBD, 0x9E, 0x13, 0x33, 0x57, 0xA7,
	0x15, 0x49, 0xAD, 0xB1, 0xE0, 0x34, 0x01, 0x96,
	0xEB, 0xB5, 0x56, 0xEA, 0x11, 0x11, 0x48, 0x4A,
	0x40, 0x93, 0x16, 0x79, 0x0C, 0xD0, 0xD7, 0xC5,
	0x7B, 0x86, 0x23, 0x0B, 0x4D, 0x85, 0xF9, 0x66,
	0xD8, 0xF2, 0x51, 0xD0, 0x5F, 0x95, 0x6F, 0x40,
	0x5E, 0xCB, 0x78, 0xCB, 0xA5, 0x12, 0x96, 0x95,
	0x7F, 0x09, 0x72, 0xE4, 0x2E, 0xC4, 0x30, 0x4F,
	0x3B, 0x49, 0x8D, 0xEA, 0x37, 0x01, 0x28, 0xC5
};

// impossible elements
u8 x_xor_sx_imp[93] = {
	0x00, 0x04, 0x07, 0x09, 0x0a, 0x0b, 0x0d, 0x0e,
	0x0f, 0x15, 0x17, 0x18, 0x1b, 0x1d, 0x23, 0x24,
	0x25, 0x26, 0x29, 0x2a, 0x2f, 0x31, 0x35, 0x36,
	0x37, 0x3b, 0x3e, 0x43, 0x46, 0x47, 0x48, 0x53,
	0x54, 0x56, 0x58, 0x5b, 0x5c, 0x5e, 0x64, 0x66,
	0x6b, 0x71, 0x76, 0x7e, 0x7f, 0x81, 0x83, 0x84,
	0x86, 0x88, 0x89, 0x8a, 0x8b, 0x94, 0x96, 0x99,
	0x9a, 0x9b, 0x9d, 0x9e, 0xa1, 0xa2, 0xa4, 0xa6,
	0xa7, 0xa8, 0xaa, 0xab, 0xac, 0xaf, 0xb2, 0xb3,
	0xbb, 0xbc, 0xbd, 0xc0, 0xc1, 0xc5, 0xca, 0xcc,
	0xce, 0xd3, 0xd5, 0xe0, 0xe1, 0xe3, 0xe5, 0xea,
	0xf3, 0xf9, 0xfa, 0xfd, 0xff
};

int main2() {
	int i, N = 16777216;
	clock_t t1;
	time_t w1;
	FILE *ou;

	if ((ou=fopen("out.txt", "w")) == NULL)
		pf("Cannot open file");

	t1 = clock();
	w1 = time(NULL);

	for (i=0; i<N; i++) {
		fpf(ou, "%d", i);
	}

	pf("CPU Time  : %f seconds\n", (clock() - t1) / (double)(CLOCKS_PER_SEC));
	fclose(ou);

	return 0;
}

int main() {
	//u16 key[3] = { 0xC3F0, 0x30FF, 0x6696 };
	u16 key[16];
	u32 masterkey = 0x0000C3F0;
	s8 i;
	u8 Nr;
	u8 keylen;

	u64 masterkey64 = 0;
	u64 key64[12];
	u16 x;

	// AES 64-bit Block

	/*
	 *
	//sbox4x4_8bit_Construct();
	pf("Test NibbleSub64 -> %016llX\n", NibbleSub64(0x0123456789ABCDEF));

	pf("Test NibbleSub64Inv -> %016llX\n", NibbleSub64Inv(NibbleSub64(0x0123456789ABCDEF)));

	pf("Test ShiftRow64    -> %016llX\n", ShiftRow64(0x0123456789ABCDEF));
	pf("Test ShiftRow64Inv -> %016llX\n", ShiftRow64Inv(ShiftRow64(0x0123456789ABCDEF)));

	pf("Nibble1 %X\n", MixColumn64_Nibble1(0x0123));
	pf("Nibble2 %X\n", MixColumn64_Nibble2(0x0123));
	pf("Nibble3 %X\n", MixColumn64_Nibble3(0x0123));
	pf("Nibble4 %X\n", MixColumn64_Nibble4(0x0123));
	u64 m64 = 0x0123456789ABCDEF;
	pf("Test MixColumn64    -> %016llX\n", MixColumn64(m64));
	pf("Test MixColumn64Inv -> %016llX\n", MixColumn64Inv(MixColumn64(m64)));
	//MixColumn64_Table_Construct();
	 *
	 */
	// key schedule
	/*
	keySchedule64(masterkey64, key64);

	pf("Number of rounds = %d\n", R);
	// encrypt
	u64 c64 = 0x9C63000011112222;
	pf("\nptext = %016llX\n", c64);
	pf("subkeys =\n"); for (i=0; i<(R+2); i++) pf("%016llX\n", key64[i]); pf("\n");

	c64 = encrypt64(c64, key64);
	pf("Encrypt -> %016llX\n\n", c64);

	pf("ctext = %016llX\n", c64);
	pf("subkeys =\n"); for (i=(R+1); i>=0; i--) pf("%016llX\n", key64[i]); pf("\n");
	c64 = decrypt64(c64, key64);
	pf("Decrypt -> %016llX\n", c64);

	u8 index = 3;
	u64 subkey = key64[index];
	pf("Test computing backwards %016llX : %016llX [%016llX]\n", subkey, subkeyComputeBackward(subkey, index), key64[index-1]);
	pf("Test computing forwards  %016llX : %016llX [%016llX]\n", subkey, subkeyComputeForward(subkey, index), key64[index+1]);
	*/
	// AES 64-bit Block

	//*
	pf("Testing je %x\n", NibbleSub(0x0123));
	pf("Test ShiftRow -> %04X\n", ShiftRow(0x4567));
	//MixColumn_Table_Construct();

	/*
	 * The following is the test vectors provided in Raphael's paper
	 * plaintext : 0x09C63
	 * secret key: 0xC3F0
	 * ciphertext: 0x72C6
	 *
	 * round subkeys:
	 *  - round 0: 0xC3F0
	 *  - round 1: 0x30FF
	 *  - round 2: 0x6696
	 */
	u16 c = 0x9C63; // the plaintext in Raphael's paper

	c = 0;
	masterkey = 0x0000C3F0;
	keylen = 4;

	// key schedule
	keySchedule(masterkey, key, keylen, &Nr);

	// encrypt
	pf("\nptext = %04X\n", c);
	pf("subkeys = "); for (i=0; i<(Nr+1); i++) pf("%04X ", key[i]); pf("\n");

	c = encrypt(c, key, Nr);
	pf("Encrypt -> %04X\n\n", c);

	pf("ctext = %04X\n", c);
	pf("subkeys = "); for (i=Nr; i>=0; i--) pf("%04X ", key[i]); pf("\n");
	c = decrypt(c, key, Nr);
	pf("Decrypt -> %04X\n", c);
	//*/

	check_for_same_key();
    //check_for_same_key_fix_key();
    //analyze_mini_aes_key_sch();
    //analyze_mini_aes_a();
//	print_n_choose_2();
    
    //print_latex_x_xor_sx();
	//print_x_xor_sx_preimage(0xc2);
	//analysis_x_xor_sx();

	/*
	for (x = 0; x < 256; ++x) {
		solve_key_eqns(x);
	}
	*/

	//build_mult_by_x_table(3);
	//print_latex_x_xor_2sx();
	//print_latex_x_xor_3sx();

	//analysis_x_xor_2sx();
	//analysis_x_xor_3sx();
	return 0;
}

u32 factorial(u16 n) {
	u32 i, x=1;

	for (i = 1; i <= n; ++i) {
		x = x * i;
	}

	return x;
}

u32 factorial_offset(u16 n, u8 offset) {
	u32 i, x=1;

	for (i = (n-offset+1); i <= n; ++i) {
		x = x * i;
	}

	return x;
}

u16 calc_n_choose_2(u16 n) {
	//pf(" [%d %d] ", factorial(n), factorial(n-2));
	return (factorial_offset(n, 2)/2);
}

void print_n_choose_2() {
	u16 i, n;

	n = 40;
	for (i = 0; i < 2; ++i) {
		pf("%3d, ", 0);
	}
	for (i = 2; i < n; ++i) {
		//pf("%d %d\n", i, calc_n_choose_2(i));
		pf("%3d, ", calc_n_choose_2(i));
	}
}

#define PRINT_TO_FILE
/*
 * This function deals with fixing a plaintext and varying the keys to
 * search for collision
 */
void check_for_same_key() {
	struct utsname uname_pointer; // to obtain system information
	u16 key[16];
	u16 keyRef[16]; // the reference key, in our case, the all-zero key
	u32 masterkey = 0x0000C3F0;
	u64 i;
	u8 j, k;
	u8 Nr;
	u8 keylen;
	u32 ci;
	u16 c, cx, x;
	u64 max, count=1, clen, total_all=0, total_comb=0, count_plaintexts=0;

	// array for n choose 2. The index refers to n
	u16 n_choose_2[40] = {   0,   0,   1,   3,   6,  10,  15,  21,  28,  36,
							45,  55,  66,  78,  91, 105, 120, 136, 153, 171,
						   190, 210, 231, 253, 276, 300, 325, 351, 378, 406,
						   435, 465, 496, 528, 561, 595, 630, 666, 703, 741 };

	FILE *ou;
	uname(&uname_pointer);

	/*
	 * new structure for file name (starting 2 Jul 2018)
	 *  - out-mini-aes[key length in bits]: e.g.: out-mini-aes16
	 *  - [number of rounds]r
	 *  - nod: no details (optional), if stated, then details regarding the keys will not be printed
	 *  - pf2: print format version 2
	 */
	if ((ou=fopen("out-mini-aes16-2r-nod-pf2.txt", "w")) == NULL)
		pf("Cannot open file");

	// deprecated as at 5 Jul 2018
	//if ((ou=fopen("out-mini-aes16-3r.txt", "w")) == NULL)
	//	pf("Cannot open file");

	clock_t t1;
	time_t w1;

	t1 = clock();
	w1 = time(NULL);
	fpf(ou, "\n");
	timestamp();

	keylen = 4;

	max = (u64)pow(2, keylen*4);

	// limitation
	if (keylen == 6) {
		max = (u64)pow(2, 17);
	}

	pf("max = %lu\n", max);

	clen = (u64)pow(2, 16);

	for (ci = 0; ci < clen; ++ci) {

		cx = c = ci;
		masterkey = 0;
		// [0] KEY SCHEDULE
		// the typical MiniAES
		keySchedule(masterkey, keyRef, keylen, &Nr);
        Nr = 2; // override, if you want

		// [A] testing no key schedule but subkey the same in all rounds
        // the MiniAES-A
		/*
		Nr = 2;
		for (j = 0; j < (Nr+1); ++j) {
			key[j] = masterkey;
		}
		*/

		// [B] testing no key schedule: the 1st subkey is the same as masterkey, the rest are all zeros
        // the MiniAES-B
		/*
		Nr = 10;
		key[0] = masterkey;
		for (j = 1; j < (Nr+1); ++j) {
			key[j] = 0;
		}

		// for keylen=6, 8
		key[ 0] = ((masterkey & 0xffff0000) >> 16);
		key[Nr] =   masterkey & 0x0000ffff;
		*/

		//fpf(ou, "subkeys = "); for (i=0; i<(Nr+1); i++) fpf(ou, "%04X ", key[i]); fpf(ou, "\n");
		x = encrypt(cx, key, Nr);

		//same_key_analysis(cx, key, Nr);
		for (i = 1; i < max; ++i) {
			masterkey = i;

			// [0] KEY SCHEDULE
			// the typical MiniAES
			keySchedule(masterkey, key, keylen, &Nr);
            Nr = 2; // override, is you want

			// [A] testing no key schedule but subkey the same in all rounds
            // the MiniAES-A
			/*
			Nr = 2;
			for (j = 0; j < (Nr+1); ++j) {
				key[j] = masterkey;
			}
			*/

			// [B] testing no key schedule: the 1st subkey is the same as masterkey, the rest are all zeros
            // the MiniAES-B
			/*
			Nr = 10;

			key[0] = masterkey;
			for (j = 1; j < (Nr+1); ++j) {
				key[j] = 0;
			}

			// for keylen=6, 8
			key[ 0] = ((masterkey & 0xffff0000) >> 16);
			key[Nr] =   masterkey & 0x0000ffff;

			*/

			if (encrypt(c, key, Nr) == x) {

#ifdef PRINT_TO_FILE
				// old way of printing
				/*
				fpf(ou, "(m,k) = (%x %x)\n", c, i);
				fpf(ou, "subkeys = ");

				for (j=0; j<(Nr+1); j++)
					fpf(ou, "%04X ", key[j]);
				*/

				// new print format to save space (print format version 2: pf2):
				// key :: subkeys
				fpf(ou, "%x :: ", i);
				for (j=0; j<(Nr+1); j++)
					fpf(ou, "%04X ", key[j]);
				fpf(ou, "\n");
#endif

				//same_key_analysis(c, key, Nr);
				count++; // counting number of keys that yield the collision
			}
		}

		if (count > 1) {
			count_plaintexts++; // increment the plaintext count

			// print the all-zero keys
#ifdef PRINT_TO_FILE
			fpf(ou, "%x :: ", masterkey);
			for (j=0; j<(Nr+1); j++)
				fpf(ou, "%04X ", keyRef[j]);
			fpf(ou, "\n");

			fpf(ou, "Total: %d; p = %x c = %x\n\n", count, cx, x);
#endif
			total_all += count;
			total_comb += n_choose_2[count];

			count = 1; // reset to 1
		}
	}

	fpf(ou, "Total number of keys: %d\n\n", total_all);
	fpf(ou, "Total number of plaintexts: %d\n\n", count_plaintexts);
	fpf(ou, "Average number keys per plaintext that yield collision: %f\n\n", total_all*1.0/count_plaintexts*1.0);
	fpf(ou, "Number of colliding pairs: %d\n\n", total_comb);

	fpf(ou, "\nDONE!!\n\n");

	fpf(ou,"System name - %s \n", uname_pointer.sysname);
	fpf(ou,"Nodename    - %s \n", uname_pointer.nodename);
	fpf(ou,"Release     - %s \n", uname_pointer.release);
	fpf(ou,"Version     - %s \n", uname_pointer.version);
	fpf(ou,"Machine     - %s \n\n", uname_pointer.machine);
	//fpf(ou,"Domain name - %s n", uname_pointer.domainname);

	fpf(ou, "CPU Time : %f seconds\n", (clock() - t1) / (double)(CLOCKS_PER_SEC));
	fpf(ou, "Wall Time: %f seconds\n", (double)time(NULL) - (double)w1);

	pf("CPU Time : %f seconds\n", (clock() - t1) / (double)(CLOCKS_PER_SEC));
	pf("Wall Time: %f seconds\n", (double)time(NULL) - (double)w1);
	timestamp();
	fclose(ou);
}

/*
 * This function deals with fixing a KEY and varying the PLAINTEXT to
 * search for collision
 */
void check_for_same_key_fix_key() {
    u16 key[16];
    u32 masterkey = 0x0000C3F0;
    u64 i;
    u8 j, k;
    u8 Nr;
    u8 keylen;
    u32 ci;
    u32 m;
    u16 cx;
    u64 max, count=1, mlen, total_all=0, total_comb=0, count_keys=0;
    
    // array for n choose 2. The index refers to n
    u16 n_choose_2[40] = {   0,   0,   1,   3,   6,  10,  15,  21,  28,  36,
        45,  55,  66,  78,  91, 105, 120, 136, 153, 171,
        190, 210, 231, 253, 276, 300, 325, 351, 378, 406,
        435, 465, 496, 528, 561, 595, 630, 666, 703, 741 };
    
    FILE *ou;
    
    if ((ou=fopen("outputs-mini-aes17-2r-comb-fix-key.txt", "w")) == NULL)
        pf("Cannot open file");
    
    clock_t t1;
    time_t w1;
    
    t1 = clock();
    w1 = time(NULL);
    fpf(ou, "\n");
    timestamp();
    
    keylen = 6;
    
    max = (u64)pow(2, keylen*4);
    
    // limitation
    if (keylen >= 6) {
        max = (u64)pow(2, 17);
    }
    
    pf("max key length = %lu\n", max);
    
    mlen = (u64)pow(2, 16);
    
    
    for (i = 0; i < max; ++i) {
        masterkey = i;
        
        // [0] KEY SCHEDULE
        keySchedule(masterkey, key, keylen, &Nr);
        Nr = 2; // override, if you want
        
        // [A] testing no key schedule but subkey the same in all rounds
        /*
         Nr = 2;
         for (j = 0; j < (Nr+1); ++j) {
         key[j] = masterkey;
         }
         */
        
        // [B] testing no key schedule: the 1st subkey is the same as mastekey, the rest are all zeros
        /*
         Nr = 10;
         
         key[0] = masterkey;
         for (j = 1; j < (Nr+1); ++j) {
         key[j] = 0;
         }
         
         // for keylen=6, 8
         key[ 0] = ((masterkey & 0xffff0000) >> 16);
         key[Nr] =   masterkey & 0x0000ffff;
         
         */
        
        m = 0;
        cx = encrypt(m, key, Nr);
        
        for (m=1; m<mlen; m++) {
            if (encrypt(m, key, Nr) == cx) {
                fpf(ou, "(m,k) = (%x %x)\n", m, i);
                fpf(ou, "subkeys = "); for (j=0; j<(Nr+1); j++) fpf(ou, "%04X ", key[j]); fpf(ou, "\n");
                
                //same_key_analysis(c, key, Nr);
                count++; // counting number of plaintexts that yield the collision
            }
        }
        
        if (count > 1) {
            count_keys++; // increment the key count
            
            fpf(ou, "Total: %d; c = %x\n\n", count, cx);
            
            total_all += count;
            total_comb += n_choose_2[count];
            
            count = 1; // reset to 1
        }
    }
    
    
    fpf(ou, "Total number of plaintexts: %d\n\n", total_all);
    fpf(ou, "Total number of keys: %d\n\n", count_keys);
    fpf(ou, "Average number of plaintexts per key that yield collision: %f\n\n", total_all*1.0/count_keys*1.0);
    fpf(ou, "Number of colliding pairs: %d\n\n", total_comb);
    
    fpf(ou, "\nDONE!!\n");
    
    fpf(ou, "CPU Time : %f seconds\n", (clock() - t1) / (double)(CLOCKS_PER_SEC));
    fpf(ou, "Wall Time: %f seconds\n", (double)time(NULL) - (double)w1);
    
    pf("CPU Time : %f seconds\n", (clock() - t1) / (double)(CLOCKS_PER_SEC));
    pf("Wall Time: %f seconds\n", (double)time(NULL) - (double)w1);
    timestamp();
    fclose(ou);
}

void same_key_analysis(u16 c, u16 *key, u8 Nr) {
	encrypt_print(c, key, Nr);
}

void analyze_mini_aes_key_sch() {
    u16 m;
    u16 key1[16];
    u16 key2[16];
    u32 masterkey1 = 0x0000;
    u32 masterkey2 = 0xc193;
    u8 i;
    u8 j, k;
    u8 Nr;
    u8 keylen = 4;
    u16 c1, c2;
    
    keySchedule(masterkey1, key1, keylen, &Nr);
    keySchedule(masterkey2, key2, keylen, &Nr);
    
    // override
    Nr = 2;
    
    pf("subkeys1 = "); for (i=0; i<(Nr+1); i++) pf("%04X ", key1[i]); pf("\n");
    pf("subkeys2 = "); for (i=0; i<(Nr+1); i++) pf("%04X ", key2[i]); pf("\n");
    
    m = 0xffff;
    c1 = encrypt_print(m, key1, Nr);
    c2 = encrypt_print(m, key2, Nr);
    
}

void analyze_mini_aes_a() {
    u16 m;
    u16 key1[16];
    u16 key2[16];
    u32 masterkey1 = 0x0000;
    u32 masterkey2 = 0x3333;
    u8 i;
    u8 j, k;
    u8 Nr;
    u8 keylen = 4;
    u16 c1, c2;
    
    // override
    Nr = 2;
    
    pf("subkeys1 = ");
    for (i=0; i<(Nr+1); i++) {
        key1[i] = masterkey1;
        pf("%04X ", key1[i]);
    }
    pf("\n");
    pf("subkeys2 = ");
    for (i=0; i<(Nr+1); i++) {
        key2[i] = masterkey2;
        pf("%04X ", key2[i]);
    }
    pf("\n");
    
    m = 0xffff;
    c1 = encrypt_print(m, key1, Nr);
    c2 = encrypt_print(m, key2, Nr);
    
}

void print_latex_x_xor_sx() {
    int i, j;
    
    printf(" & ");
    for (i=0; i<16; i++) {
        printf("\\texttt{%X}", i);
        if (i<15) {
            printf(" &");
        }
    }
    printf("\\\\\n");
    
    for (i=0; i<16; i++) {
        printf("\\texttt{%X} & ", i);
        for (j=0; j<16; j++) {
            printf("\\texttt{%02X} ", ((i*16)+j) ^ aes_sbox[(i*16)+j]);
            if (j<15) {
                printf("& ");
            }
            
            if ((j%7)==0) {
                printf("\n");
            }
        }
        printf("\\\\\n");
    }
    
    // print for C
    printf("\n\n");
    for (i = 0; i < 16; ++i) {
		for (j = 0; j < 16; ++j) {

            if (((j%8)==0) && (j>0)) {
                printf("\n");
            }

			printf("0x%02X, ", ((i*16)+j) ^ aes_sbox[(i*16)+j]);
		}
		printf("\n");
	}

}

void print_latex_x_xor_2sx() {
    int i, j;

    printf(" & ");
    for (i=0; i<16; i++) {
        printf("\\texttt{%X}", i);
        if (i<15) {
            printf(" &");
        }
    }
    printf("\\\\\n");

    for (i=0; i<16; i++) {
        printf("\\texttt{%X} & ", i);
        for (j=0; j<16; j++) {
            printf("\\texttt{%02X} ", ((i*16)+j) ^ aes_multby2[aes_sbox[(i*16)+j]]);
            if (j<15) {
                printf("& ");
            }

            if ((j%7)==0) {
                printf("\n");
            }
        }
        printf("\\\\\n");
    }

    // print for C
    printf("\n\n");
    for (i = 0; i < 16; ++i) {
		for (j = 0; j < 16; ++j) {

            if (((j%8)==0) && (j>0)) {
                printf("\n");
            }

			printf("0x%02X, ", ((i*16)+j) ^ aes_multby2[aes_sbox[(i*16)+j]]);
		}
		printf("\n");
	}

}

void print_latex_x_xor_3sx() {
    int i, j;

    printf(" & ");
    for (i=0; i<16; i++) {
        printf("\\texttt{%X}", i);
        if (i<15) {
            printf(" &");
        }
    }
    printf("\\\\\n");

    for (i=0; i<16; i++) {
        printf("\\texttt{%X} & ", i);
        for (j=0; j<16; j++) {
            printf("\\texttt{%02X} ", ((i*16)+j) ^ aes_multby3[aes_sbox[(i*16)+j]]);
            if (j<15) {
                printf("& ");
            }

            if ((j%7)==0) {
                printf("\n");
            }
        }
        printf("\\\\\n");
    }

    // print for C
    printf("\n\n");
    for (i = 0; i < 16; ++i) {
		for (j = 0; j < 16; ++j) {

            if (((j%8)==0) && (j>0)) {
                printf("\n");
            }

			printf("0x%02X, ", ((i*16)+j) ^ aes_multby3[aes_sbox[(i*16)+j]]);
		}
		printf("\n");
	}

}

void print_x_xor_sx_preimage(u8 x) {
	u16 i;

	for (i = 0; i < 256; ++i) {
		if (x_xor_sx_table[i] == x) {
			pf("%02X ", i);
		}
	}
}

void analysis_x_xor_sx() {
	u8 element[256] = { 0 };
	u16 i, count=0;
	u8 highest_count = 0;
	u8 element_w_highest_count = 0;

	for (i = 0; i < 256; ++i) {
		element[x_xor_sx_table[i]]++;
	}

	// count and print number of impossible elements
	pf("Impossible elements:\n");
	for (i = 0; i < 256; ++i) {
		if (element[i] == 0) {
			count++;
			pf("%02x ", i);
			//pf("0x%02x, ", i);
		}
	}
	pf("\nTotal = %d (%.2f), Diff = %d\n", count, count*1.0/(256*1.0), 256-count);

	pf("Possible elements count:\n");
	for (i = 0; i < 256; ++i) {
		if ((i%16)==0) {
			pf("\n");
		}

		if (element[i] > 0) {
			pf("%02x (%d) ", i, element[i]);
			//pf("0x%02x, ", i);

			if (element[i] > highest_count) {
				highest_count = element[i];
				element_w_highest_count = i;
			}
		}
	}
	pf("\nExample of element with highest count, i.e. = %d (there may be more) = %02x\n", element_w_highest_count);
}

void analysis_x_xor_2sx() {
	u8 element[256] = { 0 };
	u16 i, count=0;
	u8 highest_count = 0;
	u8 element_w_highest_count = 0;

	for (i = 0; i < 256; ++i) {
		element[x_xor_2sx_table[i]]++;
	}

	// count and print number of impossible elements
	pf("Impossible elements:\n");
	for (i = 0; i < 256; ++i) {
		if (element[i] == 0) {
			count++;
			pf("%02x ", i);
			//pf("0x%02x, ", i);
		}
	}
	pf("\nTotal = %d (%.2f), Diff = %d\n", count, count*1.0/(256*1.0), 256-count);

	pf("Possible elements count:\n");
	for (i = 0; i < 256; ++i) {
		if ((i%16)==0) {
			pf("\n");
		}

		if (element[i] > 0) {
			pf("%02x (%d) ", i, element[i]);
			//pf("0x%02x, ", i);

			if (element[i] > highest_count) {
				highest_count = element[i];
				element_w_highest_count = i;
			}
		}
	}
	pf("\nExample of element with highest count, i.e. = %d (there may be more) = %02x\n", element_w_highest_count);
}

void analysis_x_xor_3sx() {
	u8 element[256] = { 0 };
	u16 i, count=0;
	u8 highest_count = 0;
	u8 element_w_highest_count = 0;

	for (i = 0; i < 256; ++i) {
		element[x_xor_3sx_table[i]]++;
	}

	// count and print number of impossible elements
	pf("Impossible elements:\n");
	for (i = 0; i < 256; ++i) {
		if (element[i] == 0) {
			count++;
			pf("%02x ", i);
			//pf("0x%02x, ", i);
		}
	}
	pf("\nTotal = %d (%.2f), Diff = %d\n", count, count*1.0/(256*1.0), 256-count);

	pf("Possible elements count:\n");
	for (i = 0; i < 256; ++i) {
		if ((i%16)==0) {
			pf("\n");
		}

		if (element[i] > 0) {
			pf("%02x (%d) ", i, element[i]);
			//pf("0x%02x, ", i);

			if (element[i] > highest_count) {
				highest_count = element[i];
				element_w_highest_count = i;
			}
		}
	}
	pf("\nExample of element with highest count, i.e. = %d (there may be more) = %02x\n", element_w_highest_count);
}

/*
 * This function return 0 if the XOR requested is impossible
 */
u8 return_w(u8 w_xor, u8 *w, u8 *count) {
	u16 i, j;

	// check for impossibility
	for (i = 0; i < 93; ++i) {
		if (w_xor == x_xor_sx_imp[i]) {
			return 0;
		}
	}

	j = 0;
	for (i = 0; i < 256; ++i) {
		if (w_xor == x_xor_sx_table[i]) {
			w[j] = i;
			j++;
		}
	}
	*count = j;
	return 1;
}

/*
 * attempting to solve the key equations
 */
void solve_key_eqns(u8 w0) {
	u8 w_pos[16][4]; // possible values for w
	u8 s_w15;
	u8 w[16]; // the single selected value for w
	u8 imp_status; // status whether impossible or not
	u8 count_w0 , count_w1 , count_w2 , count_w3 , count_w4,
	   count_w5 , count_w6 , count_w7 , count_w8,
	   count_w9 , count_w10, count_w11, count_w12,
	   count_w13, count_w14, count_w15;
	u16 i0, i1, i2 , i3 , i4 , i5 , i6 , i7 ,
	    i8, i9, i10, i11, i12, i13, i14, i15;
	u8 i, tmp;

	// guess w0
	w[0] = w0;
	pf("w_0: %02X\n", w0);

	// eq 1
	s_w15 = aes_sbox[w0] ^ w0;
	pf("s(w_15): %02X\n", s_w15);
	w[15] = aes_sbox_inv[s_w15];

	pf("w_15: %02X\n", w[15]);

	imp_status = return_w(s_w15, w_pos[0], &count_w0);

	if (imp_status == 0) {
		pf("  w_0 = %02X not possible\n");
	}

	for (i0 = 0; i0 < count_w0; ++i0) {
		w[0] = w_pos[0][i0];
		pf("w_0: %02X ", w[0]);

		imp_status = return_w(w0 ^ s_w15, w_pos[1], &count_w1);
		printf("imp_status: %d -- %02X\n", imp_status, w0 ^ s_w15);

		if (imp_status==0) {
			continue;
		}

		pf("\n  count = %d ( ", count_w1);
		for (i = 0; i < count_w1; ++i) {
			pf("%02X ", w_pos[1][i]);
		}
		pf(")\n");

		for (i1 = 0; i1 < count_w1; ++i1) {
			w[1] = w_pos[1][i1];
			pf("w_1: %02X ", w[1]);

			imp_status = return_w(w0 ^ s_w15 ^ w[1], w_pos[2], &count_w2);
			pf("imp_status: %d -- %02X\n", imp_status, w0 ^ s_w15 ^ w[1]);

			if (imp_status==0) {
				continue;
			}

			pf("\n  count = %d ( ", count_w2);
			for (i = 0; i < count_w2; ++i) {
				pf("%02X ", w_pos[2][i]);
			}
			pf(")\n");

			for (i2 = 0; i2 < count_w2; ++i2) {
				w[2] = w_pos[2][i2];
				pf("w_2: %02X ", w[2]);

				imp_status = return_w(w0 ^ s_w15 ^ w[1] ^ w[2], w_pos[3], &count_w3);
				pf("imp_status: %d -- %02X\n", imp_status, w0 ^ s_w15 ^ w[1] ^ w[2]);

				if (imp_status==0) {
					continue;
				}

				pf("\n  count = %d ( ", count_w3);
				for (i = 0; i < count_w3; ++i) {
					pf("%02X ", w_pos[3][i]);
				}
				pf(")\n");

				for (i3 = 0; i3 < count_w3; ++i3) {
					w[3] = w_pos[3][i3];
					pf("w_3: %02X ", w[3]);

					tmp = w0 ^ s_w15 ^ w[1] ^ w[2] ^ w[3];
					imp_status = return_w(tmp, w_pos[4], &count_w4);
					pf("imp_status: %d -- %02X\n", imp_status, tmp);

					if (imp_status==0) {
						continue;
					}

					pf("\n  count = %d ( ", count_w4);
					for (i = 0; i < count_w4; ++i) {
						pf("%02X ", w_pos[4][i]);
					}
					pf(")\n");

					for (i4 = 0; i4 < count_w4; ++i4) {
						w[4] = w_pos[4][i4];
						pf("w_4: %02X ", w[4]);

						tmp = w0 ^ s_w15 ^ w[1] ^ w[2] ^ w[3] ^ w[4];
						imp_status = return_w(tmp, w_pos[5], &count_w5);
						pf("imp_status: %d -- %02X\n", imp_status, tmp);

						if (imp_status==0) {
							continue;
						}

						pf("\n  count = %d ( ", count_w5);
						for (i = 0; i < count_w5; ++i) {
							pf("%02X ", w_pos[5][i]);
						}
						pf(")\n");

						for (i5 = 0; i5 < count_w5; ++i5) {
							w[5] = w_pos[5][i5];
							pf("w_5: %02X ", w[5]);

							tmp = w0 ^ s_w15 ^ w[1] ^ w[2] ^ w[3] ^ w[4] ^ w[5];
							imp_status = return_w(tmp, w_pos[6], &count_w6);
							pf("imp_status: %d -- %02X\n", imp_status, tmp);

							if (imp_status==0) {
								continue;
							}

							pf("\n  count = %d ( ", count_w6);
							for (i = 0; i < count_w6; ++i) {
								pf("%02X ", w_pos[6][i]);
							}
							pf(")\n");

							for (i6 = 0; i6 < count_w6; ++i6) {
								w[6] = w_pos[6][i6];
								pf("w_6: %02X ", w[6]);

								tmp = w0 ^ s_w15 ^ w[1] ^ w[2] ^ w[3] ^ w[4] ^ w[5] ^ w[6];
								imp_status = return_w(tmp, w_pos[7], &count_w7);
								pf("imp_status: %d -- %02X\n", imp_status, tmp);

								if (imp_status==0) {
									continue;
								}

								pf("\n  count = %d ( ", count_w7);
								for (i = 0; i < count_w7; ++i) {
									pf("%02X ", w_pos[7][i]);
								}
								pf(")\n");

								for (i7 = 0; i7 < count_w7; ++i7) {
									w[7] = w_pos[7][i7];
									pf("w_7: %02X ", w[7]);

									tmp = w0 ^ s_w15 ^ w[1] ^ w[2] ^ w[3] ^ w[4] ^ w[5] ^ w[6] ^ w[7];
									imp_status = return_w(tmp, w_pos[8], &count_w8);
									pf("imp_status: %d -- %02X\n", imp_status, tmp);

									if (imp_status==0) {
										continue;
									}

									pf("\n  count = %d ( ", count_w8);
									for (i = 0; i < count_w8; ++i) {
										pf("%02X ", w_pos[8][i]);
									}
									pf(")\n");

									for (i8 = 0; i8 < count_w8; ++i8) {
										w[8] = w_pos[8][i8];
										pf("w_8: %02X ", w[8]);

										tmp = w0 ^ s_w15 ^ w[1] ^ w[2] ^ w[3] ^ w[4] ^ w[5] ^ w[6] ^ w[7] ^
												w[8];
										imp_status = return_w(tmp, w_pos[9], &count_w9);
										pf("imp_status: %d -- %02X\n", imp_status, tmp);

										if (imp_status==0) {
											continue;
										}

										pf("\n  count = %d ( ", count_w9);
										for (i = 0; i < count_w9; ++i) {
											pf("%02X ", w_pos[9][i]);
										}
										pf(")\n");

										for (i9 = 0; i9 < count_w9; ++i9) {
											w[9] = w_pos[9][i9];
											pf("w_9: %02X ", w[9]);

											tmp = w0 ^ s_w15 ^ w[1] ^ w[2] ^ w[3] ^ w[4] ^ w[5] ^ w[6] ^ w[7] ^
													w[8] ^ w[9];
											imp_status = return_w(tmp, w_pos[10], &count_w10);
											pf("imp_status: %d -- %02X\n", imp_status, tmp);

											if (imp_status==0) {
												continue;
											}

											pf("\n  count = %d ( ", count_w10);
											for (i = 0; i < count_w10; ++i) {
												pf("%02X ", w_pos[10][i]);
											}
											pf(")\n");

											for (i10 = 0; i10 < count_w10; ++i10) {
												w[10] = w_pos[10][i10];
												pf("w_10: %02X ", w[10]);

												tmp = w0 ^ s_w15 ^ w[1] ^ w[2] ^ w[3] ^ w[4] ^ w[5] ^ w[6] ^ w[7] ^
														w[8] ^ w[9] ^ w[10];
												imp_status = return_w(tmp, w_pos[11], &count_w11);
												pf("imp_status: %d -- %02X\n", imp_status, tmp);

												if (imp_status==0) {
													continue;
												}

												pf("\n  count = %d ( ", count_w11);
												for (i = 0; i < count_w11; ++i) {
													pf("%02X ", w_pos[11][i]);
												}
												pf(")\n");

												for (i11 = 0; i11 < count_w11; ++i11) {
													w[11] = w_pos[11][i11];
													pf("w_11: %02X ", w[11]);

													tmp = w0 ^ s_w15 ^ w[1] ^ w[2] ^ w[3] ^ w[4] ^ w[5] ^ w[6] ^ w[7] ^
															w[8] ^ w[9] ^ w[10] ^ w[11];
													imp_status = return_w(tmp, w_pos[12], &count_w12);
													pf("imp_status: %d -- %02X\n", imp_status, tmp);

													if (imp_status==0) {
														continue;
													}

													pf("\n  count = %d ( ", count_w12);
													for (i = 0; i < count_w12; ++i) {
														pf("%02X ", w_pos[12][i]);
													}
													pf(")\n");

													for (i12 = 0; i12 < count_w12; ++i12) {
														w[12] = w_pos[12][i12];
														pf("w_12: %02X ", w[12]);

														tmp = w0 ^ s_w15 ^ w[1] ^ w[2] ^ w[3] ^ w[4] ^ w[5] ^ w[6] ^ w[7] ^
																w[8] ^ w[9] ^ w[10] ^ w[11] ^ w[12];
														imp_status = return_w(tmp, w_pos[13], &count_w13);
														pf("imp_status: %d -- %02X\n", imp_status, tmp);

														if (imp_status==0) {
															continue;
														}

														pf("\n  count = %d ( ", count_w13);
														for (i = 0; i < count_w13; ++i) {
															pf("%02X ", w_pos[13][i]);
														}
														pf(")\n");

														for (i13 = 0; i13 < count_w13; ++i13) {
															w[13] = w_pos[13][i13];
															pf("w_13: %02X ", w[13]);

															tmp = w0 ^ s_w15 ^ w[1] ^ w[2] ^ w[3] ^ w[4] ^ w[5] ^ w[6] ^ w[7] ^
																	w[8] ^ w[9] ^ w[10] ^ w[11] ^ w[12] ^ w[13];
															imp_status = return_w(tmp, w_pos[14], &count_w14);
															pf("imp_status: %d -- %02X\n", imp_status, tmp);

															if (imp_status==0) {
																continue;
															}

															pf("\n  count = %d ( ", count_w14);
															for (i = 0; i < count_w14; ++i) {
																pf("%02X ", w_pos[14][i]);
															}
															pf(")\n");

															for (i14 = 0; i14 < count_w14; ++i14) {
																w[14] = w_pos[14][i14];
																pf("w_14: %02X ", w[14]);

																// note that s_w15 is absent in tmp below
																tmp = w0 ^ w[1] ^ w[2] ^ w[3] ^ w[4] ^ w[5] ^ w[6] ^ w[7] ^
																		w[8] ^ w[9] ^ w[10] ^ w[11] ^ w[12] ^ w[13] ^ w[14];

																pf("w_15: %02X == %02X?\n", w[15], tmp);

																if (tmp == w[15]) {
																	pf("***** OK!! ");
																	for (i = 0; i < 15; ++i) {
																		pf("%02X ", w[i]);
																	}
																	pf("*****\n");
																}

															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}

				}
			}

		}
	}
	pf("\n----------- end %02X --------------\n", w0);
}

// related to AES
// check whether the leftmost bit of the value is 1
u8 LMBCheck(u32 val) {
    return ((val & 0x80) >> 7); // returns 1 or 0
}

/* perform multiplication in GF(2^8)
multiplication of a value by x (i.e., by [02]) can be implemented as
a 1-bit left shift followed by a conditional bitwise XOR with 0001 1011 {1b}
if the leftmost bit of the original value (prior to the shift) is 1.
*/
u32 multiply(u8 stateVal, u8 axVal) {
    u8 status;
    u32 aVal, sVal, result=0;

    aVal = axVal; sVal = stateVal;

    while (aVal != 0) {
        if ( (aVal & 1) != 0 )
            result ^= sVal;

        status = LMBCheck(sVal);
        sVal = sVal << 1;

        if (status == 1)
            sVal ^= 0x1b;

        sVal &= 0xff;
        aVal = (aVal & 0xff) >> 1;
    }
    return result;
}

void build_mult_by_x_table(u8 x) {
	u16 i;

	for (i = 0; i < 256; ++i) {
		if (((i%16)==0) && (i>0)) {
			pf("\n");
		}
		pf("0x%02X, ", multiply(i, x));
	}
}

void timestamp ( void ) {
	# define TIME_SIZE 40

	static char time_buffer[TIME_SIZE];
	const struct tm *tm;
	size_t len;
	time_t now;

	now = time ( NULL );
	tm = localtime ( &now );

	len = strftime ( time_buffer, TIME_SIZE, "%d %B %Y %I:%M:%S %p", tm );

	printf ( "%s\n", time_buffer );

	return;
	# undef TIME_SIZE
}
