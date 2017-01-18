#ifndef _SMAZ_H
#define _SMAZ_H

int sCompress(int level, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen);
int smaz_compress(char *in, int inlen, char *out, int outlen);

#endif
