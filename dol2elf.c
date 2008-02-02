// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "tools.h"

struct section {
	u32 addr;
	u32 size;
	u32 offset;
	u32 elf_offset;
	u32 str_offset;
};

static void dol2elf(char *inname, char *outname)
{
	u8 dolheader[0x100];
	u8 elfheader[0x400] = {0};
	u8 segheader[0x400] = {0};
	u8 secheader[0x400] = {0};
	u8 strings[0x400] = "\0.strtab";
	u32 str_offset = 9;
	struct section section[19];
	FILE *in, *out;
	u32 n_text, n_data, n_total;
	u32 entry;
	u32 elf_offset;
	u32 i;
	u8 *p;

	in = fopen(inname, "rb");
	fread(dolheader, 1, sizeof dolheader, in);

	elf_offset = 0x1000;

	// 7 text, 11 data
	for (i = 0; i < 18; i++) {
		section[i].offset = be32(dolheader + 4*i);
		section[i].addr = be32(dolheader + 0x48 + 4*i);
		section[i].size = be32(dolheader + 0x90 + 4*i);
		section[i].elf_offset = elf_offset;
		elf_offset += -(-section[i].size & -0x100);
	}

	// bss
	section[18].offset = 0;
	section[18].addr = be32(dolheader + 0xd8);
	section[18].size = be32(dolheader + 0xdc);
	section[18].elf_offset = elf_offset;

	entry = be32(dolheader + 0xe0);

	n_text = 0;
	for (i = 0; i < 7; i++)
		if (section[i].size) {
			sprintf(strings + str_offset, ".text.%d", n_text);
			section[i].str_offset = str_offset;
			str_offset += 8;
			n_text++;
		}

	n_data = 0;
	for ( ; i < 18; i++)
		if (section[i].size) {
			sprintf(strings + str_offset, ".data.%d", n_data);
			section[i].str_offset = str_offset;
			str_offset += i < 16 ? 8 : 9;
			n_data++;
		}

	n_total = n_text + n_data;
	if (section[18].size) {
		sprintf(strings + str_offset, ".bss");
		section[i].str_offset = str_offset;
		str_offset += 5;
		n_total++;
	}

	printf("%d text sections, %d data sections, %d total (includes bss)\n",
	       n_text, n_data, n_total);
	printf("entry point = %08x\n", entry);

	memset(elfheader, 0, sizeof elfheader);
	elfheader[0] = 0x7f;
	elfheader[1] = 0x45;
	elfheader[2] = 0x4c;
	elfheader[3] = 0x46;
	elfheader[4] = 0x01;
	elfheader[5] = 0x02;
	elfheader[6] = 0x01;

	wbe16(elfheader + 0x10, 2);
	wbe16(elfheader + 0x12, 0x14);
	wbe32(elfheader + 0x14, 1);
	wbe32(elfheader + 0x18, entry);
	wbe32(elfheader + 0x1c, 0x400);
	wbe32(elfheader + 0x20, 0x800);
	wbe32(elfheader + 0x24, 0);
	wbe16(elfheader + 0x28, 0x34);
	wbe16(elfheader + 0x2a, 0x20);
	wbe16(elfheader + 0x2c, n_total);
	wbe16(elfheader + 0x2e, 0x28);
	wbe16(elfheader + 0x30, n_total + 2);
	wbe16(elfheader + 0x32, 1);

	p = segheader;
	for (i = 0; i < 19; i++)
		if (section[i].size) {
			wbe32(p + 0x00, 1);
			wbe32(p + 0x04, section[i].elf_offset);
			wbe32(p + 0x08, section[i].addr);
			wbe32(p + 0x0c, section[i].addr);
			wbe32(p + 0x10, i == 18 ? 0 : section[i].size);
			wbe32(p + 0x14, section[i].size);
			wbe32(p + 0x18, i < 7 ? 5 : 6);
			wbe32(p + 0x1c, 0x20);
			p += 0x20;
		}

	p = secheader + 0x28;
	wbe32(p + 0x00, 1);
	wbe32(p + 0x04, 3);
	wbe32(p + 0x08, 0);
	wbe32(p + 0x0c, 0);
	wbe32(p + 0x10, 0xc00);
	wbe32(p + 0x14, 0x400);
	wbe32(p + 0x18, 0);
	wbe32(p + 0x1c, 0);
	wbe32(p + 0x20, 1);
	wbe32(p + 0x24, 0);
	p += 0x28;

	for (i = 0; i < 19; i++)
		if (section[i].size) {
			wbe32(p + 0x00, section[i].str_offset);
			wbe32(p + 0x04, i == 18 ? 8 : 1);
			wbe32(p + 0x08, i < 7 ? 6 : 3);
			wbe32(p + 0x0c, section[i].addr);
			wbe32(p + 0x10, section[i].elf_offset);
			wbe32(p + 0x14, section[i].size);
			wbe32(p + 0x18, 0);
			wbe32(p + 0x1c, 0);
			wbe32(p + 0x20, 0x20);
			wbe32(p + 0x24, 0);
			p += 0x28;
		}

	out = fopen(outname, "wb");
	fwrite(elfheader, 1, sizeof elfheader, out);
	fwrite(segheader, 1, sizeof segheader, out);
	fwrite(secheader, 1, sizeof secheader, out);
	fwrite(strings, 1, sizeof strings, out);

	for (i = 0; i < 19; i++)
		if (section[i].size) {
			p = malloc(section[i].size);
			fseek(in, section[i].offset, SEEK_SET);
			fread(p, 1, section[i].size, in);
			fseek(out, section[i].elf_offset, SEEK_SET);
			fwrite(p, 1, section[i].size, out);
			free(p);
		}

	fclose(out);
	fclose(in);
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <dol> <elf>\n", argv[0]);
		exit(1);
	}

	dol2elf(argv[1], argv[2]);

	return 0;
}
