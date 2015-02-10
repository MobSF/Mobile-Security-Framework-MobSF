#ifndef _LZMA_H                                                                                                                                                           
#define _LZMA_H

#include <stdio.h>
#include <stdlib.h>

int lzmaCompress(int, const unsigned char *, size_t , unsigned char *, size_t *);

#endif
