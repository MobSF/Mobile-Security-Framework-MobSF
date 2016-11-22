#include "xz.h"

#include <stdbool.h>
#include <lzma.h>

#define COMPRESSION_LEVEL 9 
#define COMPRESSION_EXTREME true 
#define INTEGRITY_CHECK LZMA_CHECK_NONE 
//LZMA_CHECK_CRC64

int xzCompress(int level, const unsigned char *data, size_t avail_in, unsigned char *odata, size_t *avail_out)
{
   uint32_t preset = COMPRESSION_LEVEL | (COMPRESSION_EXTREME ? LZMA_PRESET_EXTREME : 0);
   lzma_check check = INTEGRITY_CHECK;
   lzma_stream strm = LZMA_STREAM_INIT;

   lzma_action action;
   lzma_ret ret_xz;

   ret_xz = lzma_easy_encoder (&strm, preset, check);
//   printf("RET %d\n", ret_xz);

   action = LZMA_FINISH;

   strm.avail_in = avail_in;
   strm.next_in = data;

   strm.next_out = odata;
   strm.avail_out = *avail_out;

   ret_xz = lzma_code (&strm, action);
//   printf("RET %d\n", ret_xz);
//   printf("%d %d\n", *avail_out, strm.avail_out);

   *avail_out -= strm.avail_out;

   lzma_end (&strm);

   return 0;
}
