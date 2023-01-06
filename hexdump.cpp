#include <stdio.h>
#include <string.h>

#include "hexdump.h"

void hexDump(unsigned char const * const buffer, unsigned int bufferLen, FILE* fd, bool asciiToo)
{
   char asciiDump[0x11];
   char const * const ASCII_BLANK = "                ";
   strcpy(asciiDump, ASCII_BLANK);

   unsigned int i;
   for(i = 0; i < bufferLen; i++)
   {
      if ( (buffer[i] >= ' ') && (buffer[i] <= '~') )
      {
         // Printable in ASCII
         asciiDump[i % 16] = buffer[i];
      }
      else
      {
         // Not printable ASCII
         asciiDump[i % 16] = '.';
      }

      fprintf(fd, "%02x", buffer[i]);
      if (i % 16 == 15)
      {
         if (asciiToo)
         {
            fprintf(fd, "  |%s|\n", asciiDump);
            strcpy(asciiDump, ASCII_BLANK);
         }
         else
         {
            fprintf(fd, "\n");
         }
      }
      else if (i % 16 == 7)
      {
         fprintf(fd, "  ");
      }
      else
      {
         fprintf(fd, " ");
      }
   }

   if (i % 16 != 0)
   {
      if (asciiToo)
      {
         // Need to print out padding before ascii
         for (int paddingByte = ( i % 16); paddingByte < 16; paddingByte++)
         {
            fprintf(fd, "   ");
         }

         if ((i % 16) < 8)
         {
            // There is an extra space between byte 8 and 9 that must be accounted for
            fprintf(fd, " ");
         }

         fprintf(fd, " |%s|\n", asciiDump);
         strcpy(asciiDump, ASCII_BLANK);
      }
      else
      {
         fprintf(fd, "\n");
      }
   }
}



