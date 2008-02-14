// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
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
static u8 header[0xf0c0];

static void output_image(u8 *data, u32 w, u32 h, const char *name)
{
	FILE *fp;
	u32 x, y;

	fp = fopen(name, "wb");
	if (!fp)
		fatal("open %s", name);

	fprintf(fp, "P6 %d %d 255\n", w, h);

	for (y = 0; y < h; y++)
		for (x = 0; x < w; x++) {
			u8 pix[3];
			u16 raw;
			u32 x0, x1, y0, y1, off;

			x0 = x & 3;
			x1 = x >> 2;
			y0 = y & 3;
			y1 = y >> 2;
			off = x0 + 4 * y0 + 16 * x1 + 4 * w * y1;

			raw = be16(data + 2*off);

			// RGB5A3
			if (raw & 0x8000) {
				pix[0] = (raw >> 7) & 0xf8;
				pix[1] = (raw >> 2) & 0xf8;
				pix[2] = (raw << 3) & 0xf8;
			} else {
				pix[0] = (raw >> 4) & 0xf0;
				pix[1] =  raw       & 0xf0;
				pix[2] = (raw << 4) & 0xf0;
			}

			if (fwrite(pix, 3, 1, fp) != 1)
				fatal("write %s", name);
		}

	fclose(fp);
}

static void do_file_header(void)
{
	u8 md5_file[16];
	u8 md5_calc[16];
	u32 header_size;
	char name[256];
	char dir[17];
	FILE *out;
	u32 i;

	if (fread(header, sizeof header, 1, fp) != 1)
		fatal("read file header");

	aes_cbc_dec(sd_key, sd_iv, header, sizeof header, header);

	memcpy(md5_file, header + 0x0e, 16);
	memcpy(header + 0x0e, md5_blanker, 16);
	md5(header, sizeof header, md5_calc);

	if (memcmp(md5_file, md5_calc, 0x10))
		ERROR("MD5 mismatch");

	header_size = be32(header + 8);
	if (header_size < 0x72a0 || header_size > 0xf0a0
	    || (header_size - 0x60a0) % 0x1200 != 0)
		ERROR("bad file header size");

	snprintf(dir, sizeof dir, "%016llx", be64(header));
	if (mkdir(dir, 0777))
		fatal("mkdir %s", dir);
	if (chdir(dir))
		fatal("chdir %s", dir);

	out = fopen("###title###", "wb");
	if (!out)
		fatal("open ###title###");
	if (fwrite(header + 0x40, 0x80, 1, out) != 1)
		fatal("write ###title###");
	fclose(out);

	output_image(header + 0xc0, 192, 64, "###banner###.ppm");
	if (header_size == 0x72a0)
		output_image(header + 0x60c0, 48, 48, "###icon###.ppm");
	else
		for (i = 0; 0x1200*i + 0x60c0 < header_size; i++) {
			snprintf(name, sizeof name, "###icon%d###.ppm", i);
			output_image(header + 0x60c0 + 0x1200*i, 48, 48, name);
		}
}

static void do_backup_header(void)
{
	u8 header[0x80];

	if (fread(header, sizeof header, 1, fp) != 1)
		fatal("read backup header");

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

static mode_t perm_to_mode(u8 perm)
{
	mode_t mode;
	u32 i;

	mode = 0;
	for (i = 0; i < 3; i++) {
		mode <<= 3;
		if (perm & 0x20)
			mode |= 3;
		if (perm & 0x10)
			mode |= 5;
		perm <<= 2;
	}

	return mode;
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
	mode_t mode;

	if (fread(header, sizeof header, 1, fp) != 1)
		fatal("read file header");

	if (be32(header) != 0x03adf17e)
		ERROR("bad file header");

	size = be32(header + 4);
	perm = header[8];
	attr = header[9];
	type = header[10];
	name = header + 11;

	fprintf(stderr, "file: size=%08x perm=%02x attr=%02x type=%02x name=%s\n", size, perm, attr, type, name);

	mode = perm_to_mode(perm);

	switch (type) {
	case 1:
		rounded_size = (size + 63) & ~63;
		data = malloc(rounded_size);
		if (!data)
			fatal("malloc");
		if (fread(data, rounded_size, 1, fp) != 1)
			fatal("read file data for %s", name);

		aes_cbc_dec(sd_key, header + 0x50, data, rounded_size, data);

		out = fopen(name, "wb");
		if (!out)
			fatal("open %s", name);
		if (fwrite(data, size, 1, out) != 1)
			fatal("write %s", name);
		fclose(out);

		mode &= ~0111;

		free(data);
		break;

	case 2:
		if (mkdir(name, 0777))
			fatal("mkdir %s", name);
		break;

	default:
		ERROR("unhandled file type");
	}

	if (chmod(name, mode))
		fatal("chmod %s", name);
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

	if (fread(sig, sizeof sig, 1, fp) != 1)
		fatal("read signature");
	if (fread(ng_cert, sizeof ng_cert, 1, fp) != 1)
		fatal("read NG cert");
	if (fread(ap_cert, sizeof ap_cert, 1, fp) != 1)
		fatal("read AP cert");

	data_size = total_size - 0x340;

	data = malloc(data_size);
	if (!data)
		fatal("malloc");
	fseek(fp, 0xf0c0, SEEK_SET);
	if (fread(data, data_size, 1, fp) != 1)
		fatal("read data for sig check");
	sha(data, data_size, hash);
	sha(hash, 20, hash);
	free(data);

	ok = check_ec(ng_cert, ap_cert, sig, hash);
	printf("ok: %d\n", ok);
}

int main(int argc, char **argv)
{
	u32 i;
	u32 mode;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <data.bin>\n", argv[0]);
		return 1;
	}

	get_key("sd-key", sd_key, 16);
	get_key("sd-iv", sd_iv, 16);
	get_key("md5-blanker", md5_blanker, 16);

	fp = fopen(argv[1], "rb");
	if (!fp)
		fatal("open %s", argv[1]);

	do_file_header();
	do_backup_header();

	for (i = 0; i < n_files; i++)
		do_file();

	mode = perm_to_mode(header[0x0c]);
	if (chmod(".", mode))
		fatal("chmod .");
	if (chdir(".."))
		fatal("chdir ..");

	do_sig();

	fclose(fp);

	return 0;
}
