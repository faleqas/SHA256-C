#include "sha256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


//in the SHA docs when padding an input
//1- we pad it to the nearest bigger multiple of 512 bits (if its 64 bits we pad 512-64.
//														  if its 513 we pad 1024-513
//2- we add a "1" bit at the end of the input
//3- the rest of the bits until the last 64 bits are zeroes
//4- the last 64 bits contain the original size of our original input in a 64 bit integer
//understanding this is important in order to understand this function and the rest of the code
char* 
padding_input(char* raw_input, int input_size, int* padded_size_out);

//parsing the output from padding_input()
uint32_t*
parsing_input(char* padded_input, int padded_len);

//this function chooses which bit to pick from f and g by using e's bits
//if bit 1 at e is 0 then we pick the bit from g
//if its a 1 then we pick the bit from f
uint32_t
ch(uint32_t e, uint32_t f, uint32_t g);

//this function chooses the bit that is the majority in the 3 bits and chooses it
//if the first bit of 'a' is 0
//the first bit of 'b' is 1
//the first bit of 'c' is 0
//then we choose the bit 0 as the first bit of the output
uint32_t
maj(uint32_t a, uint32_t b, uint32_t c);

uint32_t 
circular_right_shift(uint32_t x, int shift_by);
uint32_t
circular_left_shift(uint32_t x, int shift_by);

//we could also generate these constants with an algorithm on program startup but that isn't needed
const uint32_t hash_values[] = {
	0x6a09e667, //H0
	0xbb67ae85, //H1
	0x3c6ef372, //H2
	0xa54ff53a, //H3
	0x510e527f, //H4
	0x9b05688c, //H5
	0x1f83d9ab, //H6
	0x5be0cd19  //H7
};
const uint32_t k_values[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t*
SHA256(char* raw_input)
{
	int input_size = strlen(raw_input);

	int padded_size = 0;
	char* input = padding_input(raw_input, input_size, &padded_size);

	//printf("padded_size: %d bits, from %d bits or %d bytes from %d bytes\n",
		//padded_size * 8, input_size * 8, padded_size, input_size);

	uint32_t* hash = parsing_input(input, padded_size);
 	printf("\n");
	/*for (int i = 0; i < 8; i++)
	{
		printf("%08x\n", hash[i]);
	}*/

	free(input);
	return hash;
}

//مش محتاجين دي فحاجة عموما في البروجكت عشان مظنش في باسورد اطول من 64 حرف
//فا المفروض نقدر نخلي كل البادينج يبقي 512 علطول اسهل بس حبيت اعملها برضو
//output MUST BE FREED
//since the SHA docs specify in bits:
//64 bytes is 512 bits (the minimum padding)
//128 bytes is 1024 bits
//etc etc
char* 
padding_input(char* raw_input, int input_size, int* padded_size_out)
{
	int padded_size = 0;

	int prev = 64;
	for (int i = 128; ; i += 64)
	{
		//if the input is 512 bits long we still pad to 1024 to be able to add the "1" bit
		//that is specified in SHA preprocessing docs
		if (prev <= input_size)
		{
			prev = i;
			continue;
		}
		int difference_prev = abs(prev - input_size);
		int difference_current = abs(i - input_size);

		if (difference_prev < difference_current)
		{
			padded_size = prev;
			break;
		}
		else
		{
			prev = i;
			continue;
		}
	}

	char* output = (char*)calloc(padded_size, sizeof(char));
	if (output)
	{

		memcpy_s(output, padded_size, raw_input, input_size);
		output[input_size] |= 0x0001;

		//adding the length of the original input to the last 64 bits of the padded output
		//also in SHA docs
		uint64_t* output_int = (uint64_t*)output;
		int output_int_size = padded_size / 8;
		output_int[output_int_size - 1] = input_size;
		//printf("%d\n", output_int[output_int_size - 1]);

		*padded_size_out = padded_size;
		return output;
	}
	
	return NULL;
}

//TODO() if the padded input is larger than 512 bits we need to split it into multiple blocks of 512
//but due to time constraints and i need to submit the project quickly this function assumes that
//padded_len is always 512 bits or 64 bytes.
uint32_t* 
parsing_input(char* padded_input, int padded_len)
{
	uint32_t* words = (uint32_t*)padded_input; //our input is split into blocks of 32 bits (words)
	int words_count = padded_len / 4; //from 64 bytes to 16 bytes

	//this works on padded sizes 1024 and above only
	for (int i = 16; i < words_count; i++)
	{

	}

	{
		uint32_t a = hash_values[0];
		uint32_t b = hash_values[1];
		uint32_t c = hash_values[2];
		uint32_t d = hash_values[3];
		uint32_t e = hash_values[4];
		uint32_t f = hash_values[5];
		uint32_t g = hash_values[6];
		uint32_t h = hash_values[7];


		for (int i = 0; i < words_count; i++)
		{

			uint32_t sigma1e1 = circular_right_shift(e, 6);
			uint32_t sigma1e2 = circular_right_shift(e, 11);
			uint32_t sigma1e3 = circular_right_shift(e, 25);

			uint32_t sigma1e = (sigma1e1 ^ sigma1e2 ^ sigma1e3);

			uint32_t sigma0a1 = circular_right_shift(a, 2);
			uint32_t sigma0a2 = circular_right_shift(a, 13);
			uint32_t sigma0a3 = circular_right_shift(a, 22);

			uint32_t sigma0a = (sigma0a1 ^ sigma0a2 ^ sigma0a3);

			uint32_t t1 = h + sigma1e + ch(e, f, g) + k_values[0] + words[0];
			uint32_t t2 = sigma0a + maj(a, b, c);

			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}
		
		//this is our 256 bit hash result finally
		uint32_t updated_hash_values[8] =
		{
			a + hash_values[0],
			b + hash_values[1],
			c + hash_values[2],
			d + hash_values[3],
			e + hash_values[4],
			f + hash_values[5],
			g + hash_values[6],
			h + hash_values[7]
		};

		uint32_t* output = calloc(8, sizeof(uint32_t));
		memcpy_s(output, sizeof(uint32_t) * 8,
			updated_hash_values, sizeof(uint32_t) * 8);

		return output;
	}
	return NULL;
}

uint32_t
maj(uint32_t a, uint32_t b, uint32_t c)
{
	uint32_t output = 0;
	for (int i = 0; i < 32; i++)
	{
		uint32_t bit1 = (a >> i) % 2;
		uint32_t bit2 = (b >> i) % 2;
		uint32_t bit3 = (c >> i) % 2;

		uint32_t sum = bit1 + bit2 + bit3;
		if (sum <= 1)
		{
			//the majority must be 0
			//don't need to do anything the output is all 0s automatically lol
		}
		else
		{
			//the majority must be 1
			uint32_t took_bit = 0x1 << i;
			output |= took_bit;
		}
	}
}

uint32_t
ch(uint32_t e, uint32_t f, uint32_t g)
{
	uint32_t output = 0;

	for (int i = 0; i < 32; i++)
	{
		uint32_t bit = (e >> i) % 2;
		if (bit == 0)
		{
			//take from g
			uint32_t took_bit = (g >> i) % 2;
			took_bit <<= i;

			output |= (g & took_bit);
		}
		else
		{
			//take from f
			uint32_t took_bit = (f >> i) % 2;
			took_bit <<= i;

			output |= (f & took_bit);
		}
	}
}

uint32_t 
circular_right_shift(uint32_t x, int shift_by)
{
	uint32_t output = (x >> shift_by) | (x << (32 - shift_by));
}

uint32_t 
circular_left_shift(uint32_t x, int shift_by)
{
	uint32_t output = (x << shift_by) | (x >> (32 - shift_by));
}