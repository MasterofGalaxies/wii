// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "tools.h"

#define ERROR(s) do { fprintf(stderr, s "\n"); exit(1); } while (0)

static u8 sd_key[16];
static u8 sd_iv[16];
static u8 md5_blanker[16];

static FILE *fp;
static u32 n_files;
static u32 files_size;
static u32 total_size;

static void do_file_header(void)
{
	u8 header[0xf0c0];
	u8 md5_file[16];
	u8 md5_calc[16];

	fread(header, 1, sizeof header, fp);

	aes_cbc_dec(sd_key, sd_iv, header, sizeof header, header);

	memcpy(md5_file, header + 0x0e, 16);
	memcpy(header + 0x0e, md5_blanker, 16);
	md5(header, sizeof header, md5_calc);

	if (memcmp(md5_file, md5_calc, 0x10))
		ERROR("MD5 mismatch");
}

static void do_backup_header(void)
{
	u8 header[0x80];

	fread(header, 1, sizeof header, fp);

	if (be32(header + 4) != 0x426b0001)
		ERROR("no Bk header");
	if (be32(header) != 0x70)
		ERROR("wrong Bk header size");

	fprintf(stderr, "NG id: %08x\n", be32(header + 8));

	n_files = be32(header + 0x0c);
	files_size = be32(header + 0x10);
	total_size = be32(header + 0x1c);

	fprintf(stderr, "%d files\n", n_files);
}

static void do_file(void)
{
	u8 header[0x80];
	u32 size;
	u32 rounded_size;
	u8 perm, attr, type;
	char *name;
	u8 *data;
	FILE *out;

	fread(header, 1, sizeof header, fp);

	if (be32(header) != 0x03adf17e)
		ERROR("bad file header");

	size = be32(header + 4);
	perm = header[8];
	attr = header[9];
	type = header[10];
	name = header + 11;

	fprintf(stderr, "file: size=%08x perm=%02x attr=%02x type=%02x name=%s\n", size, perm, attr, type, name);

	if (type != 1)
		ERROR("unhandled: file type != 1");

	rounded_size = (size + 63) & ~63;
	data = malloc(rounded_size);
	fread(data, 1, rounded_size, fp);

	aes_cbc_dec(sd_key, header + 0x50, data, rounded_size, data);

	out = fopen(name, "wb");
	fwrite(data, 1, size, out);
	fclose(out);

	free(data);
}

static void do_sig(void)
{
	u8 sig[0x40];
	u8 ng_cert[0x180];
	u8 ap_cert[0x180];
	u8 hash[0x14];
	u8 *data;
	u32 data_size;
	int ok;

	fread(sig, 1, sizeof sig, fp);
	fread(ng_cert, 1, sizeof ng_cert, fp);
	fread(ap_cert, 1, sizeof ap_cert, fp);

	data_size = total_size - 0x340;

	data = malloc(data_size);
	fseek(fp, 0xf0c0, SEEK_SET);
	fread(data, 1, data_size, fp);
	sha(data, data_size, hash);
	sha(hash, 20, hash);
	free(data);

	ok = check_ec(ng_cert, ap_cert, sig, hash);
	printf("ok: %d\n", ok);
}

int main(int argc, char **argv)
{
	u32 i;

	get_key("sd-key", sd_key, 16);
	get_key("sd-iv", sd_iv, 16);
	get_key("md5-blanker", md5_blanker, 16);

	fp = fopen(argv[1], "rb");

	do_file_header();
	do_backup_header();
	for (i = 0; i < n_files; i++)
		do_file();
	do_sig();

	fclose(fp);

	return 0;
}
