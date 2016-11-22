#ifndef _VCBLOCKSORT_H                                                                                                                                                           
#define _VCBLOCKSORT_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <assert.h>                                                                                                                                                                              

// from http://www.complearn.org/ncd.html

#define MAXSTATES 13
#define CREDULITY 52
#define STATELOGBASE 1.532

struct BlockSortCompressionInstance {
    void *baseClass;
    int code2state[256];
    int nstates;
    int *x, *p, allocated;
};

int vcblocksortCompress(int, const unsigned char *, size_t, unsigned char *, size_t *);

#endif
