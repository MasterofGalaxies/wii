// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef _TOOLS_H
#define _TOOLS_H

// basic data types
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

u32 be32(u8 *p);
u64 be64(u8 *p);
u64 be34(u8 *p);

// crypto
void sha(u8 *data, u32 len, u8 *hash);
void get_key(const char *name, u8 *key, u32 len);
void aes_cbc_dec(u8 *key, u8 *iv, u8 *in, u32 len, u8 *out);
void decrypt_title_key(u8 *title_key_crypted, u8 *title_id, u8 *title_key);

// compression
void do_yaz0(u8 *in, u32 in_size, u8 *out, u32 out_size);

// error handling
void fatal(const char *s);

// output formatting
void print_bytes(u8 *x, u32 n);

#endif
