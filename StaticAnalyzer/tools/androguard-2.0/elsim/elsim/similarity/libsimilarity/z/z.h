#ifndef _Z_H                                                                                                                                                           
#define _Z_H

#include <stdio.h>
#include <stdlib.h>

int zCompress(int, const unsigned char *, size_t, unsigned char *, size_t *);
int zDecompress(const unsigned char *, size_t, unsigned char *, size_t *);

#endif
