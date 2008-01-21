// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include "tools.h"

#include <openssl/aes.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

//
// basic data types
//

u32 be32(u8 *p)
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

u64 be64(u8 *p)
{
	return ((u64)be32(p) << 32) | be32(p + 4);
}

u64 be34(u8 *p)
{
	return 4 * (u64)be32(p);
}

//
// crypto
//

void sha(u8 *data, u32 len, u8 *hash)
{
	SHA1(data, len, hash);
}

void get_key(const char *name, u8 *key, u32 len)
{
	char path[256];
	char *home;
	FILE *fp;

	home = getenv("HOME");
	if (home == 0)
		fatal("cannot find HOME");
	snprintf(path, sizeof path, "%s/.wii/%s", home, name);

	fp = fopen(path, "rb");
	if (fp == 0)
		fatal("cannot open common-key");
	if (fread(key, len, 1, fp) != 1)
		fatal("error reading common-key");
	fclose(fp);
}

void aes_cbc_dec(u8 *key, u8 *iv, u8 *in, u32 len, u8 *out)
{
	AES_KEY aes_key;

	AES_set_decrypt_key(key, 128, &aes_key);
	AES_cbc_encrypt(in, out, len, &aes_key, iv, AES_DECRYPT);
}

void decrypt_title_key(u8 *title_key_crypted, u8 *title_id, u8 *title_key)
{
	u8 common_key[16];
	u8 iv[16];

	get_key("common-key", common_key, 16);

	memset(iv, 0, sizeof iv);
	memcpy(iv, title_id, 8);
	aes_cbc_dec(common_key, iv, title_key_crypted, 16, title_key);
}

int check_cert(u8 *data, u32 data_len, u8 *cert, u32 cert_len)
{
	return -1;
}

//
// compression
//

void do_yaz0(u8 *in, u32 in_size, u8 *out, u32 out_size)
{
	u32 nout;
	u8 bits;
	u32 nbits;
	u32 n, d, i;

	nbits = 0;
	in += 0x10;
	for (nout = 0; nout < out_size; ) {
		if (nbits == 0) {
			bits = *in++;
			nbits = 8;
		}

		if ((bits & 0x80) != 0) {
			*out++ = *in++;
			nout++;
		} else {
			n = *in++;
			d = *in++;
			d |= (n << 8) & 0xf00;
			n >>= 4;
			if (n == 0)
				n = 0x10 + *in++;
			n += 2;
			d++;

			for (i = 0; i < n; i++) {
				*out = *(out - d);
				out++;
			}
			nout += n;
		}

		nbits--;
		bits <<= 1;
	};
}

//
// error handling
//

void fatal(const char *s)
{
	perror(s);

	exit(1);
}

//
// output formatting
//

void print_bytes(u8 *x, u32 n)
{
	u32 i;

	for (i = 0; i < n; i++)
		fprintf(stderr, "%02x", x[i]);
}

void hexdump(u8 *x, u32 n)
{
	u32 i, j;

	for (i = 0; i < n; i += 16) {
		fprintf(stderr, "%04x:", i);
		for (j = 0; j < 16 && i + j < n; j++) {
			if ((j & 3) == 0)
				fprintf(stderr, " ");
			fprintf(stderr, "%02x", *x++);
		}
		fprintf(stderr, "\n");
	}
	if (n & 15)
		fprintf(stderr, "\n");
}
