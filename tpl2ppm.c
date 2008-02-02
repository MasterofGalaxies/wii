// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <stdio.h>

#include "tools.h"

static u8 buf[5000000]; // yeah yeah, static buffer, whatever

static void i4(int w, int h, int o, char *name)
{
	FILE *out;
	int x, y;

	out = fopen(name, "wb");

	fprintf(out, "P6 %d %d 255\n", w, h);

	for (y = 0; y < h; y++)
		for (x = 0; x < w; x++) {
			u8 pix[3];
			u16 raw;
			int x0, x1, y0, y1, off;
			int ww = round_up(w, 8);

			x0 = x & 7;
			x1 = x >> 3;
			y0 = y & 7;
			y1 = y >> 3;
			off = x0 + 8*y0 + 64*x1 + 8*ww*y1;

			raw = buf[o + off/2];
			if ((x0 & 1) == 0)
				raw >>= 4;
			else
				raw &= 0x0f;

			pix[0] = raw * 0x11;
			pix[1] = raw * 0x11;
			pix[2] = raw * 0x11;

			fwrite(pix, 1, 3, out);
		}

	fclose(out);
}

static void i8(int w, int h, int o, char *name)
{
	FILE *out;
	int x, y;

	out = fopen(name, "wb");

	fprintf(out, "P6 %d %d 255\n", w, h);

	for (y = 0; y < h; y++)
		for (x = 0; x < w; x++) {
			u8 pix[3];
			u16 raw;
			int x0, x1, y0, y1, off;
			int ww = round_up(w, 8);

			x0 = x & 7;
			x1 = x >> 3;
			y0 = y & 3;
			y1 = y >> 2;
			off = x0 + 8*y0 + 32*x1 + 4*ww*y1;

			raw = buf[o + off];

			pix[0] = raw;
			pix[1] = raw;
			pix[2] = raw;

			fwrite(pix, 1, 3, out);
		}

	fclose(out);
}

static void ia4(int w, int h, int o, char *name)
{
	FILE *out;
	int x, y;

	out = fopen(name, "wb");

	fprintf(out, "P6 %d %d 255\n", w, h);

	for (y = 0; y < h; y++)
		for (x = 0; x < w; x++) {
			u8 pix[3];
			u16 raw;
			int x0, x1, y0, y1, off;
			int ww = round_up(w, 8);

			x0 = x & 7;
			x1 = x >> 3;
			y0 = y & 3;
			y1 = y >> 2;
			off = x0 + 8*y0 + 32*x1 + 4*ww*y1;

			raw = buf[o + off];

			//raw = (raw >> 4) * 0x11;
			raw = (raw & 0xf) * 0x11;

			pix[0] = raw;
			pix[1] = raw;
			pix[2] = raw;

			fwrite(pix, 1, 3, out);
		}

	fclose(out);
}

static void rgb5a3(int w, int h, int o, char *name)
{
	FILE *out;
	int x, y;

	out = fopen(name, "wb");

	fprintf(out, "P6 %d %d 255\n", w, h);

	for (y = 0; y < h; y++)
		for (x = 0; x < w; x++) {
			u8 pix[3];
			u16 raw;
			int x0, x1, y0, y1, off;
			int ww = round_up(w, 4);

			x0 = x & 3;
			x1 = x >> 2;
			y0 = y & 3;
			y1 = y >> 2;
			off = x0 + 4*y0 + 16*x1 + 4*ww*y1;

			raw = buf[o + 2*off] << 8;
			raw |= buf[o + 2*off + 1];

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

			fwrite(pix, 1, 3, out);
		}

	fclose(out);
}

static u16 avg(u16 w0, u16 w1, u16 c0, u16 c1)
{
	u16 a0, a1;
	u16 a, c;

	a0 = c0 >> 11;
	a1 = c1 >> 11;
	a = (w0*a0 + w1*a1) / (w0 + w1);
	c = a << 11;

	a0 = (c0 >> 5) & 63;
	a1 = (c1 >> 5) & 63;
	a = (w0*a0 + w1*a1) / (w0 + w1);
	c |= a << 5;

	a0 = c0 & 31;
	a1 = c1 & 31;
	a = (w0*a0 + w1*a1) / (w0 + w1);
	c |= a;

	return c;
}

static void cmp(int w, int h, int o, char *name)
{
	FILE *out;
	int x, y;

	out = fopen(name, "wb");

	fprintf(out, "P6 %d %d 255\n", w, h);

	for (y = 0; y < h; y++)
		for (x = 0; x < w; x++) {
			u8 pix[3];
			u16 raw;
			u16 c[4];
			int x0, x1, x2, y0, y1, y2, off;
			int ww = round_up(w, 8);
			int ix;
			u32 px;

			x0 = x & 3;
			x1 = (x >> 2) & 1;
			x2 = x >> 3;
			y0 = y & 3;
			y1 = (y >> 2) & 1;
			y2 = y >> 3;
			off = 8*x1 + 16*y1 + 32*x2 + 4*ww*y2;

			c[0] = be16(buf + o + off);
			c[1] = be16(buf + o + off + 2);
			if (c[0] > c[1]) {
				c[2] = avg(2, 1, c[0], c[1]);
				c[3] = avg(1, 2, c[0], c[1]);
			} else {
				c[2] = avg(1, 1, c[0], c[1]);
				c[3] = 0;
			}

			px = be32(buf + o + off + 4);
			ix = x0 + 4*y0;
			raw = c[(px >> (30 - 2*ix)) & 3];

			pix[0] = (raw >> 8) & 0xf8;
			pix[1] = (raw >> 3) & 0xf8;
			pix[2] = (raw << 3) & 0xf8;

			fwrite(pix, 1, 3, out);
		}

	fclose(out);
}

int main(int argc, char **argv)
{
	FILE *in;
	u16 w, h, o, t;

	in = fopen(argv[1], "rb");
	fread(buf, 1, sizeof buf, in);
	fclose(in);

	h = be16(buf + 0x14);
	w = be16(buf + 0x16);
	t = be32(buf + 0x18);
	o = be32(buf + 0x1c);

fprintf(stderr, "type %02x -- %s\n", t, argv[1]);

	// XXX: check more header stuff here
	switch (t) {
	case 0:
		i4(w, h, o, argv[2]);
		break;

	case 1:
		i8(w, h, o, argv[2]);
		break;

	case 2:
		ia4(w, h, o, argv[2]);
		break;

	case 5:
		rgb5a3(w, h, o, argv[2]);
		break;

	case 14:
		cmp(w, h, o, argv[2]);
		break;

	default:
		fprintf(stderr, "unhandled type %02x\n", t);
	}

	return 0;
}
