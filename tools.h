#ifndef _TOOLS_H
#define _TOOLS_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

u32 be32(u8 *p);
u64 be64(u8 *p);
u64 be34(u8 *p);

void aes_cbc_dec(u8 *key, u8 *iv, u8 *in, u32 len, u8 *out);

void get_key(const char *name, u8 *key, u32 len);
void decrypt_title_key(u8 *title_key_crypted, u8 *title_id, u8 *title_key);

void fatal(const char *s);

void print_bytes(u8 *x, u32 n);

#endif
