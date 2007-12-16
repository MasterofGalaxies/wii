#include <string.h>
#include <stdio.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

FILE *disc_fp;

u64 partition_raw_offset;
u64 partition_data_offset;
u64 partition_data_size;


u8 title_key[16];
u64 title_id;

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

static void do_partition(void)
{
	u8 b[0x2c0];
	u64 po;
	u32 tmd_offset;
	u64 tmd_size;
	u32 cert_size;
	u64 cert_offset;
	u64 h3_offset;

	partition_raw_read(0, b, 0x02c0);

	memcpy(title_key, b + 0x01bf, 16);
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
	}
}

int main(int argc, char **argv)
{
	disc_fp = fopen(argv[1], "rb");

	do_disc();

	fclose(disc_fp);

	return 0;
}
