#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>

#include "tools.h"

static const u8 *rom;
static const u8 *super;
static const u8 *fat;
static const u8 *fst;

static u8 key[16];

static const u8 *map_rom(const char *name)
{
	int fd = open(name, O_RDONLY);
	void *map = mmap(0, 0x20000000, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	return map;
}

static const u8 *find_super(void)
{
	u32 newest = 0;
	const u8 *super = 0, *p;

	for (p = rom + 0x1fc00000; p < rom + 0x20000000; p += 0x40000)
		if (be32(p) == 0x53464653) {
			u32 version = be32(p + 4);
			if (super == 0 || version > newest) {
				super = p;
				newest = version;
			}
		}

	return super;
}

static void print_mode(u8 mode)
{
	int i;
	const char dir[4] = "?-d?";
	const char perm[3] = "-rw";

	fprintf(stderr, "%c", dir[mode & 3]);
	for (i = 0; i < 3; i++) {
		fprintf(stderr, "%c", perm[(mode >> 6) & 1]);
		fprintf(stderr, "%c", perm[(mode >> 6) & 2]);
		mode <<= 2;
	}
}

static void print_entry(const u8 *entry)
{
	char name[13];
	u8 mode, attr;
	u16 sub, sib;
	u32 size;
	u16 x1, uid, gid;
	u32 x3;

	memcpy(name, entry, 12);
	name[12] = 0;
	mode = entry[0x0c];
	attr = entry[0x0d];
	sub = be16(entry + 0x0e);
	sib = be16(entry + 0x10);
	size = be32(entry + 0x12);
	x1 = be16(entry + 0x16);
	uid = be16(entry + 0x18);
	gid = be16(entry + 0x1a);
	x3 = be32(entry + 0x1c);

	print_mode(mode);
	fprintf(stderr, " %02x %04x %04x %08x (%04x %08x) %s\n",
	        attr, uid, gid, size, x1, x3, name);
}

static u8 block[0x4000];

static void do_file(const u8 *entry, const char *parent_path)
{
	char name[13];
	char path[256];
	u8 iv[16];
	u16 sub;
	u32 size, this_size;
	FILE *fp;

	memcpy(name, entry, 12);
	name[12] = 0;
	sub = be16(entry + 0x0e);
	size = be32(entry + 0x12);

	if (parent_path[strlen(parent_path) - 1] == '/' || name[0] == '/')
		sprintf(path, "%s%s", parent_path, name);
	else
		sprintf(path, "%s/%s", parent_path, name);

	fp = fopen(path + 1, "wb");

	while (size) {
		this_size = size > 0x4000 ? 0x4000 : size;

		memset(iv, 0, sizeof iv);
		aes_cbc_dec(key, iv, (u8 *)rom + 0x4000*sub, 0x4000, block);

		fwrite(block, 1, this_size, fp);

		size -= this_size;
		sub = be16(fat + 2*sub);
	}

	fclose(fp);
}

static void do_entry(const u8 *entry, const char *parent_path);

static void print_dir_entries(const u8 *entry)
{
	u16 sib;

	sib = be16(entry + 0x10);

	if (sib != 0xffff)
		print_dir_entries(fst + 0x20*sib);

	print_entry(entry);
}

static void do_dir(const u8 *entry, const char *parent_path)
{
	char name[13];
	char path[256];
	u16 sub, sib;

	memcpy(name, entry, 12);
	name[12] = 0;
	sub = be16(entry + 0x0e);
	sib = be16(entry + 0x10);

	if (parent_path[strlen(parent_path) - 1] == '/' || name[0] == '/')
		sprintf(path, "%s%s", parent_path, name);
	else
		sprintf(path, "%s/%s", parent_path, name);
	fprintf(stderr, "%s:\n", path);
	if (sub != 0xffff)
		print_dir_entries(fst + 0x20*sub);
	fprintf(stderr, "\n");

	if (path[1])
		mkdir(path + 1, 0777);

	if (sub != 0xffff)
		do_entry(fst + 0x20*sub, path);
}

static void do_entry(const u8 *entry, const char *parent_path)
{
	u8 mode;
	u16 sib;

	mode = entry[0x0c];
	sib = be16(entry + 0x10);

	if (sib != 0xffff)
		do_entry(fst + 0x20*sib, parent_path);

	mode &= 3;

	switch(mode) {
	case 1:
		do_file(entry, parent_path);
		break;
	case 2:
		do_dir(entry, parent_path);
		break;
	default:
		fprintf(stderr, "unknown mode! (%d)\n", mode);
	}
}

int main(int argc, char **argv)
{
	get_key("default/nand-key", key, 16);

	rom = map_rom(argv[1]);
	super = find_super();
	fat = super + 0x0c;
	fst = fat + 0x10000;

	mkdir(argv[2], 0777);
	chdir(argv[2]);
	do_entry(fst, "");
	chdir("..");

	return 0;
}
