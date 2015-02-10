#include "lzma.h"

#include "LzmaLib.h"

int lzmaCompress(int level, const unsigned char *data, size_t avail_in, unsigned char *odata, size_t *avail_out)
{
   unsigned char outProps[5];
   size_t outPropsSize = 5;

   return LzmaCompress( odata, avail_out, data, avail_in, outProps, &outPropsSize, level, 0, -1, -1, -1, -1, -1 );
}
