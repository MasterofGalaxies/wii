#include <openssl/aes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define SPINNER_SPEED 64

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

FILE *disc_fp;

u64 partition_raw_offset;
u64 partition_data_offset;
u64 partition_data_size;
u8 h3[0x18000];

u8 disc_key[16];

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
//fprintf(stderr, "ky: "); print_bytes(disc_key, 16); fprintf(stderr, "\n");
//fprintf(stderr, "iv: "); print_bytes(iv, 16); fprintf(stderr, "\n");
	aes_cbc_dec(disc_key, iv, raw + 0x400, 0x7c00, block);
}

static void partition_read(u64 offset, u8 *data, u32 len)
{
	u8 block[0x8000];
	u32 offset_in_block;
	u32 len_in_block;

	while(len) {
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
		percent, "/|\\-"[(spin++ / SPINNER_SPEED) % 4], h, m, s);
	fflush(stderr);
}

static void do_data(const char *dirname, u64 size)
{
	u8 data[0x7c00];
	u64 offset;
	u64 remaining_size;
	u32 block_size;
	FILE *fp;

	size = (size / 0x8000) * 0x7c00;

	mkdir(dirname, 0777);
	chdir(dirname);

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

	chdir("..");
}

static void do_partition(void)
{
	u8 b[0x2c0];
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

	fprintf(stderr, "title id = %016llx\n", title_id);

	// XXX: we should check the cert chain here, and read the tmd

	tmd_offset = be32(b + 0x02a4);
	tmd_size = be34(b + 0x02a8);
	cert_size = be32(b + 0x02ac);
	cert_offset = be34(b + 0x02b0);
	h3_offset = be34(b + 0x02b4);
	partition_data_offset = be34(b + 0x02b8);
	partition_data_size = be34(b + 0x02bc);

	fprintf(stderr, "tmd offset  =  %08x\n", tmd_offset);
	fprintf(stderr, "tmd size    = %09llx\n", tmd_size);
	fprintf(stderr, "cert size   =  %08x\n", cert_size);
	fprintf(stderr, "cert offset = %09llx\n", cert_offset);
	fprintf(stderr, "data offset = %09llx\n", partition_data_offset);
	fprintf(stderr, "data size   = %09llx\n", partition_data_size);

	partition_raw_read(h3_offset, h3, 0x18000);

	// XXX: check h3 against h4 here

	snprintf(dirname, sizeof dirname, "%016llx", title_id);
	do_data(dirname, partition_data_size);
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
		fprintf(stderr, "\n\nDoing partition %d...\n", i);
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

	do_disc();

	fclose(disc_fp);

	return 0;
}
