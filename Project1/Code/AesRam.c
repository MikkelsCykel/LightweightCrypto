/*
 * AesRam.c
 *
 *  Author: Mikkel Ole Rømer
 */ 


#include <avr/io.h>
#include <avr/pgmspace.h>

//
//  main.c
//  AES8bit
//
//  Copyright © 2015 Mikkel Rømer. All rights reserved.
//

#include <avr/io.h>

static uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static uint8_t roundKey[16];
static uint8_t r = 0x1b;
static uint8_t rCon[11] ={ 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
const uint8_t sBox[256] PROGMEM=
{
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

static uint8_t x2(uint8_t a)
{
	return (a & 0x80) ? (a << 1) ^ r : a << 1;
}

static void roundKeyGeneration(uint8_t i)
{
	if(i == 0)
	{
		roundKey[0] = key[0];
		roundKey[1] = key[1];
		roundKey[2] = key[2];
		roundKey[3] = key[3];
		roundKey[4] = key[4];
		roundKey[5] = key[5];
		roundKey[6] = key[6];
		roundKey[7] = key[7];
		roundKey[8] = key[8];
		roundKey[9] = key[9];
		roundKey[10] = key[10];
		roundKey[11] = key[11];
		roundKey[12] = key[12];
		roundKey[13] = key[13];
		roundKey[14] = key[14];
		roundKey[15] = key[15];
	}
	else
	{
		uint8_t temp[4];
		temp[0] = pgm_read_word(&sBox[roundKey[13]]) ^ rCon[i];
		temp[1] = pgm_read_word(&sBox[roundKey[14]]);
		temp[2] = pgm_read_word(&sBox[roundKey[15]]);
		temp[3] = pgm_read_word(&sBox[roundKey[12]]);
		roundKey[0] ^= temp[0];
		roundKey[1] ^= temp[1];
		roundKey[2] ^= temp[2];
		roundKey[3] ^= temp[3];
		roundKey[4] ^= roundKey[0];
		roundKey[5] ^= roundKey[1];
		roundKey[6] ^= roundKey[2];
		roundKey[7] ^= roundKey[3];
		roundKey[8] ^= roundKey[4];
		roundKey[9] ^= roundKey[5];
		roundKey[10] ^= roundKey[6];
		roundKey[11] ^= roundKey[7];
		roundKey[12] ^= roundKey[8];
		roundKey[13] ^= roundKey[9];
		roundKey[14] ^= roundKey[10];
		roundKey[15] ^= roundKey[11];
	}
}

int main(int argc, const char * argv[]) {
	
	uint8_t message[16] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
	uint8_t round = 0;
	uint8_t temp;
	uint8_t temp1;
	uint8_t temp2;
	uint8_t temp3;
	
	// AddRoundkey pre-whitening
	roundKeyGeneration(round);
	message[0] ^= roundKey[0];
	message[1] ^= roundKey[1];
	message[2] ^= roundKey[2];
	message[3] ^= roundKey[3];
	message[4] ^= roundKey[4];
	message[5] ^= roundKey[5];
	message[6] ^= roundKey[6];
	message[7] ^= roundKey[7];
	message[8] ^= roundKey[8];
	message[9] ^= roundKey[9];
	message[10] ^= roundKey[10];
	message[11] ^= roundKey[11];
	message[12] ^= roundKey[12];
	message[13] ^= roundKey[13];
	message[14] ^= roundKey[14];
	message[15] ^= roundKey[15];
	
	round = round + 1;
	
	while(round < 10)
	{
		// Subbytes + Shiftrows
		message[0] = pgm_read_word(&sBox[message[0]]);
		message[4] = pgm_read_word(&sBox[message[4]]);
		message[8] = pgm_read_word(&sBox[message[8]]);
		message[12] = pgm_read_word(&sBox[message[12]]);
		
		
		temp = message[1];
		message[1] = pgm_read_word(&sBox[message[5]]);
		message[5] = pgm_read_word(&sBox[message[9]]);
		message[9] = pgm_read_word(&sBox[message[13]]);
		message[13] = pgm_read_word(&sBox[temp]);
		
		temp = message[2];
		temp1 = message[6];
		message[2] = pgm_read_word(&sBox[message[10]]);
		message[6] = pgm_read_word(&sBox[message[14]]);
		message[10] = pgm_read_word(&sBox[temp]);
		message[14] = pgm_read_word(&sBox[temp1]);
		
		temp = message[11];
		message[11] = pgm_read_word(&sBox[message[7]]);
		message[7] = pgm_read_word(&sBox[message[3]]);
		message[3] = pgm_read_word(&sBox[message[15]]);
		message[15] = pgm_read_word(&sBox[temp]);
		
		
		// MixColumns + AddRowKey
		roundKeyGeneration(round);
		temp = message[0];
		temp1 = message[1];
		temp2 = message[2];
		temp3 = message[3];
		message[0] = (x2(temp) + (x2(temp1) ^ temp1) + temp2 + temp3) ^ roundKey[0];
		message[1] = (temp + x2(temp1) + (x2(temp2) ^ temp2) + temp3) ^ roundKey[1];
		message[2] = (temp + temp1 + x2(temp2) + (x2(temp3) ^ temp3)) ^ roundKey[2];
		message[3] = ((x2(temp) ^ temp) + temp1 + temp2 + x2(temp3)) ^ roundKey[3];
		
		temp = message[4];
		temp1 = message[5];
		temp2 = message[6];
		temp3 = message[7];
		message[4] = (x2(temp) + (x2(temp1) ^ temp1) + temp2 + temp3) ^ roundKey[4];
		message[5] = (temp + x2(temp1) + (x2(temp2) ^ temp2) + temp3) ^ roundKey[5];
		message[6] = (temp + temp1 + x2(temp2) + (x2(temp3) ^ temp3)) ^ roundKey[6];
		message[7] = ((x2(temp) ^ temp) + temp1 + temp2 + x2(temp3)) ^ roundKey[7];
		
		temp = message[8];
		temp1 = message[9];
		temp2 = message[10];
		temp3 = message[11];
		message[8] = (x2(temp) + (x2(temp1) ^ temp1) + temp2 + temp3) ^ roundKey[8];
		message[9] = (temp + x2(temp1) + (x2(temp2) ^ temp2) + temp3) ^ roundKey[9];
		message[10] = (temp + temp1 + x2(temp2) + (x2(temp3) ^ temp3)) ^ roundKey[10];
		message[11] = ((x2(temp) ^ temp) + temp1 + temp2 + x2(temp3)) ^ roundKey[11];
		
		temp = message[12];
		temp1 = message[13];
		temp2 = message[14];
		temp3 = message[15];
		message[12] = (x2(temp) + (x2(temp1) ^ temp1) + temp2 + temp3) ^ roundKey[12];
		message[13] = (temp + x2(temp1) + (x2(temp2) ^ temp2) + temp3) ^ roundKey[13];
		message[14] = (temp + temp1 + x2(temp2) + (x2(temp3) ^ temp3)) ^ roundKey[14];
		message[15] = ((x2(temp) ^ temp) + temp1 + temp2 + x2(temp3)) ^ roundKey[15];
		
		// Prepare next round
		round = round + 1;
	}
	
	// Subbytes + Shiftrows + AddRoundKey
	
	roundKeyGeneration(round);
	message[0] = (pgm_read_word(&sBox[message[0]])) ^ roundKey[0];
	message[4] = (pgm_read_word(&sBox[message[4]])) ^ roundKey[4];
	message[8] = (pgm_read_word(&sBox[message[8]])) ^ roundKey[8];
	message[12] = (pgm_read_word(&sBox[message[12]])) ^ roundKey[12];
	
	
	temp = message[1];
	message[1] = (pgm_read_word(&sBox[message[5]])) ^ roundKey[1];
	message[5] = (pgm_read_word(&sBox[message[9]])) ^ roundKey[5];
	message[9] = (pgm_read_word(&sBox[message[13]])) ^ roundKey[9];
	message[13] = (pgm_read_word(&sBox[temp])) ^ roundKey[13];
	
	temp = message[2];
	temp1 = message[6];
	message[2] = (pgm_read_word(&sBox[message[10]])) ^ roundKey[2];
	message[6] = (pgm_read_word(&sBox[message[14]])) ^ roundKey[6];
	message[10] = (pgm_read_word(&sBox[temp])) ^ roundKey[10];
	message[14] = (pgm_read_word(&sBox[temp1])) ^ roundKey[14];
	
	temp = message[11];
	message[11] = (pgm_read_word(&sBox[message[7]])) ^ roundKey[11];
	message[7] = (pgm_read_word(&sBox[message[3]])) ^ roundKey[7];
	message[3] = (pgm_read_word(&sBox[message[15]])) ^ roundKey[3];
	message[15] = (pgm_read_word(&sBox[temp])) ^ roundKey[15];
	
	while(1)
	{
		//TODO:: Please write your application code
	}
}
