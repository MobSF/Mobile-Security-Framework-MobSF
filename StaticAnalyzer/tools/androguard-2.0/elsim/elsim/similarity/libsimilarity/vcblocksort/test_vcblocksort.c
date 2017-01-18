#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "vcblocksort.h"

#define LEN 30
#define LEN2 LEN*2

#define STRING1 "TOTO TOTO"
#define STRING2 "TITO TOTO"
#define STRING3 "HELLO WORLD"
#define STRING4 "HELLO GUY"
#define STRING5 "TOTO TOTO TO"

void hexdump(unsigned char * data, unsigned int amount, size_t addr)
{
  unsigned int dp;
  unsigned int p;
  const char trans[] =
    "................................ !\"#$%&'()*+,-./0123456789"
    ":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
    "nopqrstuvwxyz{|}~...................................."
    "....................................................."
    "........................................";

  for ( dp = 1; dp <= amount; dp++ )
    {
      if ( (dp % 16) == 1 )
        {
          fprintf( stdout, "%#08" PRIXPTR " | ", (uintptr_t)addr+dp-1 );
        }

      fprintf( stdout, "%02x ", data[dp-1] );
      if ( (dp % 8) == 0 && (dp % 16) != 0 )
        {
          fputs( " ", stdout );
        }
      if ( (dp % 16) == 0 )
        {
          fputs( "| ", stdout );
          p = dp;
          for ( dp -= 16; dp < p; dp++ )
            {
              fprintf( stdout, "%c", trans[data[dp]] );
            }
          fputs( "\n", stdout );
        }
    }

  if ( (amount % 16) != 0 )
    {
      p = dp = 16 - ( amount % 16 );
      for ( dp = p; dp > 0; dp-- )
        {
          fputs( "   ", stdout );
          if ( ((dp % 8) == 0) && (p != 8) )
            {
              fputs( " ", stdout );
            }
        }
      fputs( "| ", stdout );
      for ( dp = (amount - (16 - p)); dp < amount; dp++ ) {
        fprintf( stdout, "%c", trans[data[dp]] );
      }
    }

  fputs( "\n", stdout );
  return;
}    

int main(int argc, char *argv[])
{
   unsigned char data[LEN], data2[LEN2];
   size_t avail_out;
   int ret;

   memset(data2, 0, sizeof(data2));
   avail_out = sizeof(data2);

   memset(data, 0, sizeof(data));
   memcpy(data, STRING1, strlen(STRING1));
   ret = vcblocksortCompress(9, data, strlen(STRING1), data2, &avail_out);
   printf("RET = %d AVAIL OUT %" PRIdPTR "\n", ret, avail_out);

   memset(data, 0, sizeof(data));
   memcpy(data, STRING2, strlen(STRING2));
   ret = vcblocksortCompress(9, data, strlen(STRING2), data2, &avail_out);
   printf("RET = %d AVAIL OUT %" PRIdPTR "\n", ret, avail_out);

   memset(data, 0, sizeof(data));
   memcpy(data, STRING3, strlen(STRING3));
   ret = vcblocksortCompress(9, data, strlen(STRING3), data2, &avail_out);
   printf("RET = %d AVAIL OUT %" PRIdPTR "\n", ret, avail_out);

   memset(data, 0, sizeof(data));
   memcpy(data, STRING4, strlen(STRING4));
   ret = vcblocksortCompress(9, data, strlen(STRING4), data2, &avail_out);
   printf("RET = %d AVAIL OUT %" PRIdPTR "\n", ret, avail_out);
   
   memset(data, 0, sizeof(data));
   memcpy(data, STRING5, strlen(STRING5));
   ret = vcblocksortCompress(9, data, strlen(STRING5), data2, &avail_out);
   printf("RET = %d AVAIL OUT %" PRIdPTR "\n", ret, avail_out);
   
   return 0;
}
