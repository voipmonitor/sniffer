/*
** This file is a part of DSSL library.
**
** Copyright (C) 2005-2009, Atomic Labs, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

#include <ctype.h>
#include "stdinc.h"
/*VC++ needs this include file to compile on Windows Server 2008 */
#ifdef _MSC_VER
	#include <malloc.h>
#endif
#include "errors.h"

int NmDebugCatchError_disabled_log = 0;
#ifdef _DEBUG
int NmDebugCatchError( int rc, int line, const char* file  )
{
	if(!NmDebugCatchError_disabled_log)
	{
		printf( "\nDSSL error: %d at %s@%u\n", rc, file, line );
	}
	return rc;
}
#endif
void NmDebugCatchError_disable_log()
{
	NmDebugCatchError_disabled_log = 1;
}
void NmDebugCatchError_enable_log()
{
	NmDebugCatchError_disabled_log = 0;
}

/*
static void nmLogCategory( uint32_t category )
{
	switch( category & LG_SEVERITY_MASK )
	{
	case LG_SEVERITY_ERROR: puts( "<error   | " ); break;
	case LG_SEVERITY_MESSAGE: puts( "<message | " ); break;
	case LG_SEVERITY_WARNING: puts( "<warning | " ); break;
	default: puts( "<unknown | " ); break;
	}

	switch( category & ~LG_SEVERITY_MASK )
	{
	case LG_CATEGORY_GENERAL: puts( "general>" ); break;
	case LG_CATEGORY_CAPTURE: puts( "capture>" ); break;
	default: puts( "unknown>" ); break;
	}
}
*/

void nmLogMessage( uint32_t category, const char* fmt, ... )
{
  /*TODO*/
	//category;
	//fmt;
}

void DumpBuffer(const char *label, const unsigned char *data, int data_len)
{
#if 1
	int i, j;
	
	if (NULL == data)
		data_len = 0;

	printf("\nDUMP '%s' (%u)\n", label, data_len);
	for(i=0;i<data_len;i+=16) {
		printf("| ");
		for (j = 0; j < 16 && (i+j) < data_len; ++j) {
			printf("%.2x ",data[i+j]&255);
		}
		for (; j < 16; ++j)
			printf("   ");
		
		printf("| |");
		for (j = 0; j < 16 && (i+j) < data_len; ++j) {
			if(isprint(data[i+j]))
				printf("%c",data[i+j]);
			else
				printf(".");
		}
		for (; j < 16; ++j)
			printf(" ");
		printf("|\n");
	}
#endif
}
