#ifndef _SNAPPY_H
#define _SNAPPY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

int snappyCompress(int, const unsigned char *, size_t, unsigned char *, size_t *);
int snappyDecompress(const unsigned char *, size_t, unsigned char *, size_t *);

#endif
