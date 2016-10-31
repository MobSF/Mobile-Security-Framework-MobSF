/* 
   This file is part of Elsim.

   Copyright (C) 2012, Anthony Desnos <desnos at t0t0.org>
   All rights reserved.

   Elsim is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   Elsim is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of  
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with Elsim.  If not, see <http://www.gnu.org/licenses/>.
   */

#include "similarity.h"

#define M_BLOCK         1000000

unsigned char inbuf[M_BLOCK];
unsigned char outbuf[M_BLOCK];
int (*generic_Compress)(int, const unsigned char *, size_t, unsigned char *, size_t *) = zCompress;
int (*generic_Decompress)(const unsigned char *, size_t, unsigned char *, size_t *) = zDecompress;

void *alloc_buff(size_t s1, size_t s2, size_t *nsize, int *context) {
    void *addr;
    size_t max = s1;

    if (s2 > max) {
        max = s2;
    }

    if (max > M_BLOCK) {
        addr = (void *)malloc( max );
        *context = 1;
        *nsize = max;
        return addr;
    } 

    *context = 0;
    *nsize = M_BLOCK;
    return inbuf;
}

void *alloc_unbuff(size_t s1, size_t s2, size_t *nsize, int *context) {
    void *addr;
    size_t max = s1;

    if (s2 > max) {
        max = s2;
    }

    if (max > M_BLOCK) {
        addr = (void *)malloc( max );
        *context = 1;
        *nsize = max;
        return addr;
    } 

    *context = 0;
    *nsize = M_BLOCK;
    return outbuf;
}

int free_buff( void *addr, int context) {
    if ( context == 1 ){
        free( addr );
        return 0;
    }

    if (context == 0) {
        return 0;
    }

    return -1;
}

void set_compress_type(int type) {
    if (type == TYPE_Z) {
        generic_Compress = zCompress;
        generic_Decompress = zDecompress;
    } else if (type == TYPE_BZ2) {
        generic_Compress = bz2Compress;
    } else if (type == TYPE_SMAZ) {
        generic_Compress = sCompress;
    } else if (type == TYPE_LZMA) {
        generic_Compress = lzmaCompress;
    } else if (type == TYPE_XZ) {
        generic_Compress = xzCompress;
    } else if (type == TYPE_SNAPPY) {
        generic_Compress = snappyCompress;
        generic_Decompress = snappyDecompress;
    } else if (type == TYPE_VCBLOCKSORT) {
        generic_Compress = vcblocksortCompress;
    }
}

size_t compress(int level, void *orig, size_t size_orig)
{
    int context;
    size_t s1;
    size_t size_tmp_buff;
    int ret;
    void *tmp_buff;

    tmp_buff = alloc_buff( size_orig, 0, &size_tmp_buff, &context );
    s1 = size_tmp_buff;

    ret = generic_Compress( level, orig, size_orig, tmp_buff, &s1 );
    if (ret < 0) {
        free_buff( tmp_buff, context );
        return -1;
    }

    free_buff( tmp_buff, context );
    return s1;
}


int ncd(int level, libsimilarity_t *n) 
{
    int context;
    size_t s1, s2, s3;
    size_t size_tmp_buff, size_join_buff, max, min;
    int ret;
    void *tmp_buff, *joinbuff;

    //printf("%d N = 0x%x %x %d %x %d %x %x\n", level, n, n->orig, n->size_orig, n->cmp, n->size_cmp, n->corig, n->ccmp);
    //printf("ORIG = 0x%p SIZE_ORIG = 0x%x CMP = 0x%p SIZE_CMP = 0x%x 0x%x 0x%x\n", n->orig, n->size_orig, n->cmp, n->size_cmp, *(n->corig), *(n->ccmp));

    if ((n->size_orig == 0) || (n->size_cmp == 0)) {
        n->res = 1.0;
        return -1;
    }

    tmp_buff = alloc_buff( n->size_orig, n->size_cmp, &size_tmp_buff, &context );

    s1 = *(n->corig);
    if (s1 == 0) {
        s1 = size_tmp_buff;
        //printf("COMPRESS S1 ...\n");
        ret = generic_Compress(level, n->orig, n->size_orig, tmp_buff, &s1);
        //printf("S1 RET = %d AVAIL OUT %" PRIdPTR "\n", ret, s1);
        if (ret < 0) {
            free_buff( tmp_buff, context );
            return -1;
        }

        *(n->corig) = s1;
    }

    s2 = *(n->ccmp);
    if (s2 == 0) {
        s2 = size_tmp_buff;
        //printf("COMPRESS S2 ...\n");
        ret = generic_Compress(level, n->cmp, n->size_cmp, tmp_buff, &s2);
        //printf("S2 RET = %d AVAIL OUT %" PRIdPTR "\n", ret, s2);
        if (ret < 0) {
            free_buff( tmp_buff, context );
            return -1;
        }
        *(n->ccmp) = s2;
    }

    size_join_buff = n->size_orig + n->size_cmp;
    joinbuff = (void *)malloc( size_join_buff );
    if (joinbuff == NULL) {
        free_buff( tmp_buff, context );
        return -1;
    }

    memcpy(joinbuff, n->orig, n->size_orig);
    memcpy(joinbuff+n->size_orig, n->cmp, n->size_cmp);

    s3 = size_tmp_buff;
    //printf("COMPRESS S3 ...\n");
    ret = generic_Compress(level, joinbuff, size_join_buff, tmp_buff, &s3);
    free(joinbuff);

    //printf("S3 RET = %d %d AVAIL OUT %" PRIdPTR "\n", ret, size_join_buff, s3);
    if (ret < 0) {
        free_buff( tmp_buff, context );
        return -1;
    }

    max = s1;
    min = s2;
    if (s2 > s1) {
        max = s2;
        min = s1;
    }

    free_buff( tmp_buff, context );


    n->res = (float)(abs(s3 - min)) / max;
    if (n->res > 1.0) {
        n->res = 1.0;
    }

    //printf("S3 = %" PRIdPTR " MIN = %d MAX = %d %f\n", s3, min, max, n->res);

    return 0;
}

int ncs(int level, libsimilarity_t *n) 
{
    int ret = ncd( level, n );

    n->res = 1.0 - n->res;

    return ret;
}

int cmid(int level, libsimilarity_t *n) 
{
    int context;
    size_t s1, s2, s3;
    size_t size_tmp_buff, size_join_buff, max, min;
    int ret;
    void *tmp_buff, *joinbuff;

    //printf("ORIG = 0x%x SIZE_ORIG = 0x%x CMP = 0x%x SIZE_CMP = 0x%x 0x%x 0x%x\n", (unsigned int)(n->orig), n->size_orig, (unsigned int)(n->cmp), n->size_cmp, *(n->corig), *(n->ccmp));

    tmp_buff = alloc_buff( n->size_orig, n->size_cmp, &size_tmp_buff, &context );

    s1 = *(n->corig);
    if (s1 == 0) {
        s1 = size_tmp_buff;
        ret = generic_Compress(level, n->orig, n->size_orig, tmp_buff, &s1);
        //printf("RET = %d AVAIL OUT %d\n", ret, s1);
        if (ret < 0) {
            free_buff( tmp_buff, context );
            return -1;
        }

        *(n->corig) = s1;
    }

    s2 = *(n->ccmp);
    if (s2 == 0) {
        s2 = size_tmp_buff;
        ret = generic_Compress(level, n->cmp, n->size_cmp, tmp_buff, &s2);
        //printf("RET = %d AVAIL OUT %d\n", ret, s2);
        if (ret < 0) {
            free_buff( tmp_buff, context );
            return -1;
        }
        *(n->ccmp) = s2;
    }

    size_join_buff = n->size_orig + n->size_cmp;
    joinbuff = (void *)malloc( size_join_buff );
    if (joinbuff == NULL) {
        free_buff( tmp_buff, context );
        return -1;
    }

    memcpy(joinbuff, n->orig, n->size_orig);
    memcpy(joinbuff+n->size_orig, n->cmp, n->size_cmp);

    s3 = size_tmp_buff;
    ret = generic_Compress(level, joinbuff, size_join_buff, tmp_buff, &s3);
    free(joinbuff);

    //printf("RET = %d %d AVAIL OUT %d\n", ret, size_join_buff, s3);
    if (ret < 0) {
        free_buff( tmp_buff, context );
        return -1;
    }

    max = s1;
    min = s2;
    if (s2 > s1) {
        max = s2;
        min = s1;
    }

    free_buff( tmp_buff, context );
    n->res = (float)(s1 + s2 - s3)/min;
    return 0;
}

double entropy(void *orig, size_t size_orig)
{
    double e;
    char a;
    int i;
    int byte_counters[256];
    char *c_orig = orig;

    e = 0.0;
    memset(byte_counters, '\0', sizeof(byte_counters));

    for(i=0; i < size_orig; i++) {
        a = c_orig[i];
        byte_counters[ (int)a ] ++;
    }  

    for (i=0; i < 256; i++) {
        double p_i  = (double)byte_counters[i] / (double)size_orig;
        if (p_i > 0.0) {
            e += - p_i*log2( p_i );
        }
    }

    return e;
}

unsigned int kolmogorov(int level, void *orig, size_t size_orig)
{
    int context;
    size_t size_compress_buff, s, ret;
    void *compress_buff;


    compress_buff = alloc_buff( size_orig, size_orig, &size_compress_buff, &context );
    
    s = size_compress_buff;
    ret = generic_Compress(level, orig, size_orig, compress_buff, &s);

    return s;
}

/* Haypo */

double RDTSC(void) {
#if defined linux || defined __APPLE__
    unsigned long long x;
    __asm__ volatile (".byte 0x0f, 0x31" : "=A"(x));
    return (double)x;
#else
    unsigned long a, b;
    double x;
    asm
    {
        db 0x0F, 0x31
            mov [a], eax
            mov [b], eax
    }

    x = b;
    x *= 4294967296;
    x += a;
    return x;
#endif
}

double bennett(int level, void *orig, size_t size_orig)
{
    int i, npass, context, context2;
    double t0, t1, res, moy;
    size_t size_compress_buff, size_uncompress_buff, s, su, ret;
    void *compress_buff, *uncompress_buff;


    compress_buff = alloc_buff( size_orig, size_orig, &size_compress_buff, &context );
    s = size_compress_buff;
    ret = generic_Compress(level, orig, size_orig, compress_buff, &s);
    
    //printf("COMPRESS %d %d\n", ret, s);

    uncompress_buff = alloc_unbuff( size_orig, size_orig, &size_uncompress_buff, &context2 );

    moy = 0;
    npass = 1000;
    //npass = 1;


    for(i = 0; i < npass; i++) {
        su = size_uncompress_buff;
        t0 = RDTSC();
        ret = generic_Decompress(compress_buff, s, uncompress_buff, &su);
        t1 = RDTSC();
        res = t1 - t0;
        moy += res;
        //printf("TMPBEN %d %d %f %s\n", ret, su, res, uncompress_buff);
    }
    
//    printf("BEN %f\n", moy  / npass);

    free_buff( compress_buff, context );
    free_buff( uncompress_buff, context2 );
    
    return moy / npass;
}



#ifndef MIN
# define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
size_t levenshtein(const u_int8_t *a, size_t alen, const u_int8_t *b, size_t blen)
{
    size_t tmplen, i, j;
    const u_int8_t *tmp;
    int *current, *previous, *tmpl, add, del, chg, r;

    /* Swap to reduce worst-case memory requirement */
    if (alen > blen) {
        tmp = a;
        a = b;
        b = tmp;
        tmplen = alen;
        alen = blen;
        blen = tmplen;
    }

    if (alen == 0)
        return (blen);

    if ((previous = calloc(alen + 1, sizeof(*previous))) == NULL)
        return (-1);
    if ((current = calloc(alen + 1, sizeof(*current))) == NULL) {
        free(current);
        return (-1);
    }

    for (i = 0; i < alen + 1; i++)
        previous[i] = i;

    for (i = 1; i < blen + 1; i++) {
        if (i > 1) {
            memset(previous, 0, (alen + 1) * sizeof(*previous));
            tmpl = previous;
            previous = current;
            current = tmpl;
        }
        current[0] = i;
        for (j = 1; j < alen + 1; j++) {
            add = previous[j] + 1;
            del = current[j - 1] + 1;
            chg = previous[j - 1];
            if (a[j - 1] != b[i - 1])
                chg++;
            current[j] = MIN(add, del);
            current[j] = MIN(current[j], chg);
        }
    }
    r = current[alen];
    free(previous);
    free(current);
    return (r);
}
