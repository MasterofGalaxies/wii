// Copyright 2007-2009  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <stdlib.h>
#include <stdio.h>

#include "tools.h"

static u8 buf[0x20000];
u32 slot_len;


static void slot_checksum(u32 slot)
{
	u32 i, len;
	u32 sum;
	u8 *x = buf + 0x10 + slot_len*slot;

	len = slot_len - 4;

	if (be32(buf + 4*slot) == 0) {
		printf("slot empty\n");
		return;
	}

	sum = 0x005c0999;
	for (i = 0x2c; i < len; i += 4)
		sum += be32(x + i);

	printf("slot: calc = %08x, file = %08x", sum, be32(x + len));

	if (be32(x + len) != sum) {
		wbe32(x + len, sum);
		printf("  --> fixed.");
	}

	printf("\n");
}

static void save_checksum(u8 *x)
{
	u32 i, len;
	u32 sum;

	if (slot_len == 0) {
		// HACK
		//
		// LIJ has longer slots, try it first; if that results in
		// a 0 in the "file checksum" field, try LSW instead, then LBM
		slot_len = 0x7fb0;		// LIJ
		if (be32(x + 0x10 + 4*slot_len) == 0)
			slot_len = 0x7e7c;	// LSW
		if (be32(x + 0x10 + 4*slot_len) == 0)
			slot_len = 0x7e48;	// LBM
	}


	for (i = 0; i < 4; i++)
		slot_checksum(i);

	len = 0x10 + 4*slot_len;

	sum = 0xdeadbeef;
	for (i = 0; i < len; i++)
		sum += x[i];

	printf("save: calc = %08x, file = %08x", sum, be32(x + len));

	if (be32(x + len) != sum) {
		wbe32(x + len, sum);
		printf("  --> fixed.");
	}

	printf("\n");
}

int main(int argc, char **argv)
{
	FILE *fp;

	if (argc != 2 && argc != 3) {
		fprintf(stderr, "Usage: %s <FILE_V28> [slot length]\n", argv[0]);
		return 1;
	}

	if (argc == 3)
		slot_len = atoi(argv[2]);

	fp = fopen(argv[1], "rb+");
	if (!fp)
		fatal("open %s", argv[1]);
	if (fread(buf, 0x20000, 1, fp) != 1)
		fatal("read %s", argv[1]);

	save_checksum(buf);

	if (fseek(fp, 0, SEEK_SET))
		fatal("seek");
	if (fwrite(buf, 0x20000, 1, fp) != 1)
		fatal("write %s", argv[1]);
	fclose(fp);

	return 0;
}
