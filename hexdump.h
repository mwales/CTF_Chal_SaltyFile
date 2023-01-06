#ifndef HEX_DUMP
#define HEX_DUMP

#include <stdio.h>

void hexDump(unsigned char const * const buffer, unsigned int bufferLen, FILE* fd = stdout, bool asciiToo = true);

#endif
