#include "bz2.h"

#include <bzlib.h>

int bz2Compress(int level, const unsigned char *data, size_t avail_in, unsigned char *odata, size_t *avail_out)
{
   int ret;
   int verbosity = 0;
   int workFactor = 30;
   bz_stream strm;

   strm.bzalloc = NULL;
   strm.bzfree = NULL;   
   strm.opaque = NULL;

   ret = BZ2_bzCompressInit(&strm, level, verbosity, workFactor);
   if (ret != BZ_OK) return ret;

   strm.next_in = data;
   strm.next_out = odata;
   strm.avail_in = avail_in;
   strm.avail_out = *avail_out;

   ret = BZ2_bzCompress ( &strm, BZ_FINISH );
   if (ret == BZ_FINISH_OK) goto output_overflow;
   if (ret != BZ_STREAM_END) goto errhandler;
   
   /* normal termination */   
   *avail_out -= strm.avail_out;
   BZ2_bzCompressEnd ( &strm );                                                                                                                                                    
   return BZ_OK;
   
   output_overflow:
      BZ2_bzCompressEnd ( &strm );      
      return BZ_OUTBUFF_FULL;

   errhandler:   
      BZ2_bzCompressEnd ( &strm );

   return ret;
}
