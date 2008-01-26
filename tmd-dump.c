#include <stdio.h>

#include "tools.h"

int main(int argc, char **argv)
{
	FILE *fp;
	u8 tmd[0x2000];

	fp = fopen(argv[1], "rb");
	fread(tmd, 1, sizeof tmd, fp);
	fclose(fp);

	dump_tmd(tmd);

	return 0;
}
