/******************************************************************************/
/**
@file		dbstorage.h
@author		Graeme Douglas
@brief		The databases storage layer.
@details	Provides an abstract API for interacting with various storage
		backends.
@copyright	Copyright 2013 Graeme Douglas
@license	Licensed under the Apache License, Version 2.0 (the "License");
		you may not use this file except in compliance with the License.
		You may obtain a copy of the License at
			http://www.apache.org/licenses/LICENSE-2.0

@par
		Unless required by applicable law or agreed to in writing,
		software distributed under the License is distributed on an
		"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
		either express or implied. See the License for the specific
		language governing permissions and limitations under the
		License.
*/
/******************************************************************************/

#ifndef DBSTORAGE_H
#define DBSTORAGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../db_ctconf.h"
#include "../ref.h"
#include <stdio.h>
#include <stdlib.h>

#if DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_CONTIKI

#include "contiki.h"
#include "cfs/cfs.h"

typedef int db_fileref_t;

#ifndef DB_STORAGE_NOFILE
#define DB_STORAGE_NOFILE -1
#else
#error "NAME CLASH ON DB_STORAGE_NOFILE!"
#endif

#elif DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_ARDUINO

#include "SD_c_iface.h"

typedef SD_File* db_fileref_t;

#ifndef DB_STORAGE_NOFILE
#define DB_STORAGE_NOFILE NULL
#else
#error "NAME CLASH ON DB_STORAGE_NOFILE!"
#endif

#else

typedef FILE* db_fileref_t;

#ifndef DB_STORAGE_NOFILE
#define DB_STORAGE_NOFILE NULL
#else
#error "NAME CLASH ON DB_STORAGE_NOFILE!"
#endif

#endif

/**
@typedef	db_fileref_t
@brief		An abstract reference to a file.
@details	As an example, @c FILE* is used for standard systems, and
		@c int is used for ContikiOS.  In general, this should
		almost always be a pointer type or some sort of integral
		reference number type.
*/

/**
@brief		Check to see if a file exists.
@param		filename	The name of the file.
@returns	@c 1 if the file exists, @c 0 if it does not.
*/
db_int db_fileexists(char *filename);

/**
@brief		Open a file for reading.
@param		filename		The name of the file to open.
@returns	A reference to the file to be read.
*/
void db_openreadfile(char *filename, TEE_ObjectHandle table, int db_id);

/**
@brief		Open a file for (reading and?) writing.
@param		filename		The name of the file to open.
@returns	A reference to the file to read/write.
*/
void db_openwritefile(char *filename, TEE_ObjectHandle newtable, int db_id);

/**
@brief		Open a file for appending to.
@param		filename		The name of the file to open.
@returns	A reference to the file to write to.
*/
void db_openappendfile(char *filename, TEE_ObjectHandle table, int db_id);

/**
@brief		Read from the current position in the file.
@param		f			A reference to the file to read
					from.
@param		dest			The memory location to place
					the read data in.
@param		numbytes		The number of bytes to read.
@returns	The number of bytes successfully read.
*/
int db_fileread(TEE_ObjectHandle f,
		unsigned char *dest,
		size_t numbytes);

/**
@brief		Write to the current position in the file.
@param		f			A reference to the file to write
					to.
@param		towrite			The memory location to read data
					from.
@param		numbytes		The number of bytes to write.
@returns	The number of bytes successfully written.
*/
void db_filewrite(TEE_ObjectHandle f,
		void *towrite,
		size_t numbytes);

/**
@brief		Set the files internal position back to the beginning.
@param		f	A reference to the file to rewound.
@returns	@c 1 if the file was rewound, @c 0 otherwise.
*/
db_int db_filerewind(TEE_ObjectHandle f);

/**
@brief		Move the files internal position based on where it currently is.
@param		f	A reference to the file whose position is to be changed.
@param		size	The number of bytes to move the position by.
@returns	@c 1 if the position was successfully modified, @c 0 otherwise.
*/
void db_fileseek(TEE_ObjectHandle f,
		size_t size);

/**
@brief		Close a file.
@param		f	A reference to the file to close.
@return		@c 1 if the file was closed successfully, @c 0 otherwise.
*/
void db_fileclose(TEE_ObjectHandle f);

/**
@brief		Delete a file given its name.
@param		filename	The name of the file to delete.
@return		@c 1 if the file was removed, @c 0 otherwise.
*/
void db_fileremove(char *filename, TEE_ObjectHandle table);

#ifdef __cplusplus
}
#endif

#endif
