// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <openssl/aes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

static int just_a_partition = 1;
static int dump_partition_data = 0;
static u32 max_size_to_auto_analyse = 0x1000000;
static int uncompress_yaz0 = 1;
static int unpack_rarc = 1;

static FILE *disc_fp;

static u64 partition_raw_offset;
static u64 partition_data_offset;
static u64 partition_data_size;
static u8 h3[0x18000];

static u8 disc_key[16];

static void print_bytes(u8 *x, u32 n)
{
	u32 i;

	for (i = 0; i < n; i++)
		fprintf(stderr, "%02x", x[i]);
}

static void aes_cbc_dec(u8 *key, u8 *iv, u8 *in, u32 len, u8 *out)
{
	AES_KEY aes_key;

	AES_set_decrypt_key(key, 128, &aes_key);
	AES_cbc_encrypt(in, out, len, &aes_key, iv, AES_DECRYPT);
}

static void decrypt_title_key(u8 *title_key, u8 *title_id)
{
	u8 common_key[16];
	u8 iv[16];
	FILE *fp;

	fp = fopen("common-key", "rb");
	fread(common_key, 1, 16, fp);
	fclose(fp);

	memset(iv, 0, sizeof iv);
	memcpy(iv, title_id, 8);

	aes_cbc_dec(common_key, iv, title_key, 16, disc_key);
}

static u32 be32(u8 *p)
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static u64 be64(u8 *p)
{
	return ((u64)be32(p) << 32) | be32(p + 4);
}

static u64 be34(u8 *p)
{
	return 4 * (u64)be32(p);
}

static void seek(u64 offset)
{
	fseeko(disc_fp, offset, SEEK_SET);
}

static void disc_read(u64 offset, u8 *data, u32 len)
{
	seek(offset);
	fread(data, 1, len, disc_fp);
}

static void partition_raw_read(u64 offset, u8 *data, u32 len)
{
	disc_read(partition_raw_offset + offset, data, len);
}

static void partition_read_block(u64 blockno, u8 *block)
{
	u8 raw[0x8000];
	u8 iv[16];
	u64 offset;

	offset = partition_data_offset + 0x8000 * blockno;
	partition_raw_read(offset, raw, 0x8000);

	// XXX: check H0, H1, H2 here

	memcpy(iv, raw + 0x3d0, 16);
	aes_cbc_dec(disc_key, iv, raw + 0x400, 0x7c00, block);
}

static void partition_read(u64 offset, u8 *data, u32 len)
{
	u8 block[0x8000];
	u32 offset_in_block;
	u32 len_in_block;

	if (just_a_partition)
		disc_read(offset, data, len);
	else while(len) {
		offset_in_block = offset % 0x7c00;
		len_in_block = 0x7c00 - offset_in_block;
		if (len_in_block > len)
			len_in_block = len;
		partition_read_block(offset / 0x7c00, block);
		memcpy(data, block + offset_in_block, len_in_block);
		data += len_in_block;
		offset += len_in_block;
		len -= len_in_block;
	}
}

static void spinner(u64 x, u64 max)
{
	static u32 spin;
	static time_t start_time;
	static u32 expected_total;
	u32 d;
	double percent;
	u32 h, m, s;

	if (x == 0) {
		start_time = time(0);
		expected_total = 300;
	}

	if (x == max) {
		fprintf(stderr, "Done.                    \n");
		return;
	}

	d = time(0) - start_time;

	if (d != 0)
		expected_total = (15 * expected_total + d * max / x) / 16;

	if (expected_total > d)
		d = expected_total - d;
	else
		d = 0;

	h = d / 3600;
	m = (d / 60) % 60;
	s = d % 60;
	percent = 100.0 * x / max;

	fprintf(stderr, "%5.2f%% (%c) ETA: %d:%02d:%02d  \r",
		percent, "/|\\-"[(spin++ / 64) % 4], h, m, s);
	fflush(stderr);
}

static void do_data(u64 size)
{
	u8 data[0x7c00];
	u64 offset;
	u64 remaining_size;
	u32 block_size;
	FILE *fp;

	size = (size / 0x8000) * 0x7c00;

	fp = fopen("###dat###", "wb");

	fprintf(stderr, "\nDumping partition contents...\n");
	offset = 0;
	remaining_size = size;
	while (remaining_size) {
		spinner(offset, size);

		block_size = 0x7c00;
		if (block_size > remaining_size)
			block_size = remaining_size;

		partition_read(offset, data, block_size);
		fwrite(data, 1, block_size, fp);

		offset += block_size;
		remaining_size -= block_size;
	}
	spinner(0, 0);

	fclose(fp);
}

static void copy_file(const char *name, u64 offset, u64 size)
{
	u8 data[0x80000];
	FILE *fp;
	u32 block_size;

	fp = fopen(name, "wb");

	while (size) {
		block_size = sizeof data;
		if (block_size > size)
			block_size = size;

		partition_read(offset, data, block_size);
		fwrite(data, 1, block_size, fp);

		offset += block_size;
		size -= block_size;
	}

	fclose(fp);
}

static void do_yaz0(u8 *in, u32 in_size, u8 *out, u32 out_size)
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

static void do_fst_file(const char *name, u64 offset, u64 size)
{
	FILE *fp;
	u8 *data;

	if (size > max_size_to_auto_analyse) {
		copy_file(name, offset, size);

		return;
	}

	data = malloc(size);
	partition_read(offset, data, size);

	if (uncompress_yaz0 && size >= 8 && memcmp(data, "Yaz0", 4) == 0) {
		u8 *dec;
		u32 dec_size;

		fprintf(stderr, " [Yaz0]");

		dec_size = be32(data + 4);
		dec = malloc(dec_size);

		do_yaz0(data, size, dec, dec_size);

		free(data);
		data = dec;
		size = dec_size;
	}

	if (unpack_rarc && size >= 8 && memcmp(data, "RARC", 4) == 0) {
		fprintf(stderr, " [RARC]");
	}

	fp = fopen(name, "wb");
	fwrite(data, 1, size, fp);
	fclose(fp);

	free(data);
}

static u32 do_fst(u8 *fst, const char *names, u32 i, char *indent, int is_last)
{
	u64 offset;
	u32 size;
	const char *name;
	u32 parent;
	u32 j;

	name = names + (be32(fst + 12*i) & 0x00ffffff);
	size = be32(fst + 12*i + 8);

	if (i == 0) {
		fprintf(stderr, "/\n");

		for (j = 1; j < size; )
			j = do_fst(fst, names, j, indent, (j == size - 1));

		return size;
	}

	if (fst[12*i]) {
		parent = be32(fst + 12*i + 4);
		is_last = (be32(fst + 12*parent + 8) == size);
	}

	fprintf(stderr, "%s%c-- %s", indent, "|+"[is_last], name);

	if (fst[12*i]) {
		mkdir(name, 0777);
		chdir(name);

		fprintf(stderr, "\n");

		if (is_last)
			strcat(indent, "    ");
		else
			strcat(indent, "|   ");

		for (j = i + 1; j < size; )
			j = do_fst(fst, names, j, indent, (j == size - 1));

		indent[strlen(indent) - 4] = 0;

		chdir("..");

		return size;
	} else {
		offset = be34(fst + 12*i + 4);
		do_fst_file(name, offset, size);

		fprintf(stderr, "\n");

		return i + 1;
	}
}

static void do_files(void)
{
	u8 b[0x480]; // XXX: determine actual header size
	u64 dol_offset;
	u64 fst_offset;
	u32 fst_size;
	u8 *fst;
	char indent[999];
	u32 n_files;

	partition_read(0, b, sizeof b);

	fprintf(stderr, "Title id: %c%c%c%c\n", b[0], b[1], b[2], b[3]);
	fprintf(stderr, "Group id: %c%c\n", b[4], b[5]);
	fprintf(stderr, "Name: %s\n", b + 0x20);
	fprintf(stderr, "\n");

	dol_offset = be34(b + 0x0420);
	fst_offset = be34(b + 0x0424);
	fst_size = be34(b + 0x0428);

	fprintf(stderr, "\tDOL @ %09llx\n", dol_offset);
	fprintf(stderr, "\tFST @ %09llx (size %08x)\n", fst_offset, fst_size);

	copy_file("###apl###", 0x2440, dol_offset - 0x2440);
		// XXX: wrong way to get this size, there is a header
	copy_file("###dol###", dol_offset, fst_offset - dol_offset);
		// XXX: similar, perhaps

	fst = malloc(fst_size);
	partition_read(fst_offset, fst, fst_size);
	n_files = be32(fst + 8);

	fprintf(stderr, "%d entries\n", n_files);

	indent[0] = 0;
	if (n_files > 1)
		do_fst(fst, (char *)fst + 12*n_files, 0, indent, 0);

	free(fst);
}

static void do_partition(void)
{
	u8 b[0x02c0];
	u64 title_id;
	u32 tmd_offset;
	u64 tmd_size;
	u32 cert_size;
	u64 cert_offset;
	u64 h3_offset;
	char dirname[] = "title-0000000000000000";

	partition_raw_read(0, b, 0x02c0);

	decrypt_title_key(b + 0x01bf, b + 0x01dc);

	title_id = be64(b + 0x01dc);

	fprintf(stderr, "\ttitle id = %016llx\n", title_id);

	// XXX: we should check the cert chain here, and read the tmd

	tmd_offset = be32(b + 0x02a4);
	tmd_size = be34(b + 0x02a8);
	cert_size = be32(b + 0x02ac);
	cert_offset = be34(b + 0x02b0);
	h3_offset = be34(b + 0x02b4);
	partition_data_offset = be34(b + 0x02b8);
	partition_data_size = be34(b + 0x02bc);

	fprintf(stderr, "\ttmd offset  =  %08x\n", tmd_offset);
	fprintf(stderr, "\ttmd size    = %09llx\n", tmd_size);
	fprintf(stderr, "\tcert size   =  %08x\n", cert_size);
	fprintf(stderr, "\tcert offset = %09llx\n", cert_offset);
	fprintf(stderr, "\tdata offset = %09llx\n", partition_data_offset);
	fprintf(stderr, "\tdata size   = %09llx\n", partition_data_size);

	partition_raw_read(h3_offset, h3, 0x18000);

	// XXX: check h3 against h4 here

	snprintf(dirname, sizeof dirname, "%016llx", title_id);

	mkdir(dirname, 0777);
	chdir(dirname);

	if (dump_partition_data)
		do_data(partition_data_size);

	do_files();

	chdir("..");
}

static void do_disc(void)
{
	u8 b[0x100];
	u64 partition_offset[32]; // XXX: don't know the real maximum
	u32 n_partitions;
	u32 i;

	disc_read(0, b, sizeof b);

	fprintf(stderr, "Title id: %c%c%c%c\n", b[0], b[1], b[2], b[3]);
	fprintf(stderr, "Group id: %c%c\n", b[4], b[5]);
	fprintf(stderr, "Name: %s\n", b + 0x20);
	fprintf(stderr, "\n");

	disc_read(0x40000, b, sizeof b);
	n_partitions = be32(b);

	disc_read(be34(b + 4), b, sizeof b);
	for (i = 0; i < n_partitions; i++)
		partition_offset[i] = be34(b + 8 * i);

	fprintf(stderr, "%d partitions:\n", n_partitions);
	for (i = 0; i < n_partitions; i++)
		fprintf(stderr, "\tpartition #%d @ %09llx\n", i,
		        partition_offset[i]);

	for (i = 0; i < n_partitions; i++) {
		fprintf(stderr, "\nDoing partition %d...\n", i);
		fprintf(stderr, "--------------------------------\n");

		partition_raw_offset = partition_offset[i];
		do_partition();

		//break; // XXX SII: for testing
	}
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <disc file>\n", argv[0]);
		return 1;
	}

	disc_fp = fopen(argv[1], "rb");

	if (just_a_partition)
		do_files();
	else
		do_disc();

	fclose(disc_fp);

	return 0;
}
