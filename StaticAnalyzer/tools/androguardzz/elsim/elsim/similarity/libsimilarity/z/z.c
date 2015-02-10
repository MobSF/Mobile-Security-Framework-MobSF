#include "z.h"

#include <zlib.h>


int zCompress(int level, const unsigned char *data, size_t avail_in, unsigned char *odata, size_t *avail_out)
{
   int ret;
   z_stream strm;
   
   /* allocate deflate state */
   strm.zalloc = Z_NULL;
   strm.zfree = Z_NULL;
   strm.opaque = Z_NULL;
   ret = deflateInit(&strm, level);
   if (ret != Z_OK)
      return ret;

   strm.avail_in = avail_in;
   strm.next_in = data;

   strm.next_out = odata;
   strm.avail_out = *avail_out;

   ret = deflate(&strm, Z_FINISH); 
   *avail_out -= strm.avail_out;

   (void)deflateEnd(&strm);

   return ret ? Z_OK : -1;
}

int zDecompress(const unsigned char *data, size_t avail_in, unsigned char *odata, size_t *avail_out)
{
   int ret;
   z_stream strm;
   
   /* allocate deflate state */
   strm.zalloc = Z_NULL;
   strm.zfree = Z_NULL;
   strm.opaque = Z_NULL;
   ret = inflateInit(&strm);
   if (ret != Z_OK)
      return ret;

   strm.avail_in = avail_in;
   strm.next_in = data;

   strm.next_out = odata;
   strm.avail_out = *avail_out;

   ret = inflate(&strm, Z_FINISH); 
   *avail_out -= strm.avail_out;

   (void)inflateEnd(&strm);

   return ret ? Z_OK : -1;
}
