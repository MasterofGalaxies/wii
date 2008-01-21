#include "tools.h"

#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void fatal(const char *s)
{
	perror(s);

	exit(1);
}

void print_bytes(u8 *x, u32 n)
{
	u32 i;

	for (i = 0; i < n; i++)
		fprintf(stderr, "%02x", x[i]);
}

void aes_cbc_dec(u8 *key, u8 *iv, u8 *in, u32 len, u8 *out)
{
	AES_KEY aes_key;

	AES_set_decrypt_key(key, 128, &aes_key);
	AES_cbc_encrypt(in, out, len, &aes_key, iv, AES_DECRYPT);
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

void decrypt_title_key(u8 *title_key_crypted, u8 *title_id, u8 *title_key)
{
	u8 common_key[16];
	u8 iv[16];

	get_key("common-key", common_key, 16);

	memset(iv, 0, sizeof iv);
	memcpy(iv, title_id, 8);
	aes_cbc_dec(common_key, iv, title_key_crypted, 16, title_key);
}

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
