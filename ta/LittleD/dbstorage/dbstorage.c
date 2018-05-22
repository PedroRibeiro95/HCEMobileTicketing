/******************************************************************************/
/**
@file		dbstorage.c
@author		Graeme Douglas
@brief		The databases storage layer.
@details
@see		For more information, refer to @ref dbstorage.h
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

#include "dbstorage.h"
#include "../db_ctconf.h"
#include <string.h>

db_int db_fileexists(char *filename)
{
#if DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_CONTIKI
	int check = cfs_open(filename, CFS_READ);
	if (-1 == check)
		return 0;
	
	cfs_close(check);
	return 1;
#elif DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_ARDUINO
	return SD_File_Exists(filename);
#else
	TEE_ObjectHandle newtable;
	TEE_Result res;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, filename, strlen(filename),
		flags, &newtable);
	if (res != TEE_SUCCESS)
		return 0;
	
	TEE_CloseObject(newtable);
	return 1;
#endif
}

void db_openreadfile(char *filename, TEE_ObjectHandle table)
{
#if DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_CONTIKI
	//return cfs_open(filename, CFS_READ);
#elif DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_ARDUINO
	db_fileref_t toret;
	if (1 != SD_File_Open(&toret, filename, SD_FILE_MODE_READ))
		return DB_STORAGE_NOFILE;
	//return toret;
#else
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;

	TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, filename, strlen(filename),
		flags, &table);
#endif
}

void db_openwritefile(char *filename, TEE_ObjectHandle newtable)
{
#if DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_CONTIKI
	//return cfs_open(filename, CFS_READ|CFS_WRITE);
#elif DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_ARDUINO
	SD_File_Remove(filename);
	db_fileref_t toret;
	if (1 != SD_File_Open(&toret, filename, SD_FILE_MODE_WRITE))
		//return DB_STORAGE_NOFILE;
	//return toret;
#else
	TEE_Result res;
	uint32_t flags = TEE_DATA_FLAG_OVERWRITE | TEE_DATA_FLAG_ACCESS_WRITE;
	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, filename, strlen(filename),
    flags, TEE_HANDLE_NULL, NULL, 0, &newtable);
  	if (res != TEE_SUCCESS)
    	IMSG("Error creating table...\n");
#endif
}

void db_openappendfile(char *filename, TEE_ObjectHandle table)
{
#if DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_CONTIKI
	//return cfs_open(filename, CFS_READ|CFS_WRITE|CFS_APPEND);
#elif DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_ARDUINO
	db_fileref_t toret;
	if (1 != SD_File_Open(&toret, filename, SD_FILE_MODE_WRITE))
		//return DB_STORAGE_NOFILE;
	//return toret;
#else
	//return fopen(filename, "ab");
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;

	TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, filename, strlen(filename),
		flags, &table);
#endif
}

int db_fileread(TEE_ObjectHandle f, unsigned char *dest, size_t numbytes)
{
#if DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_CONTIKI
	//return (size_t)cfs_read(f, dest, numbytes);
#elif DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_ARDUINO
	//return SD_File_Read(f, dest, numbytes);
#else
	//return numbytes*fread(dest, numbytes, 1, f);
	uint32_t read_total;
	TEE_ReadObjectData(f, dest, numbytes, &read_total);

	return read_total;
#endif
}

void db_filewrite(TEE_ObjectHandle f, void *towrite, size_t numbytes)
{
#if DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_CONTIKI
	//return (size_t)cfs_write(f, towrite, numbytes);
#elif DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_ARDUINO
	//return SD_File_Write(f, towrite, numbytes);
#else
	//return numbytes*fwrite(towrite, numbytes, 1, f);

	TEE_WriteObjectData(f, towrite, numbytes);
#endif
}

db_int db_filerewind(TEE_ObjectHandle f)
{
#if DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_CONTIKI
	return cfs_seek(f, 0, CFS_SEEK_SET);
#elif DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_ARDUINO
	return SD_File_Seek(f, 0);
#else
	//rewind(f);
	TEE_SeekObjectData(f, 0, TEE_DATA_SEEK_SET);
	return 1;
#endif
}

void db_fileseek(TEE_ObjectHandle f, size_t size)
{
#if DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_CONTIKI
	//return cfs_seek(f, size, CFS_SEEK_CUR);
#elif DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_ARDUINO
	size_t pos = SD_File_Position(f);
	//return SD_File_Seek(f, pos+size);
#else
	//return fseek(f, size, SEEK_CUR);

	TEE_SeekObjectData(f, size, TEE_DATA_SEEK_CUR);
#endif
}

void db_fileclose(TEE_ObjectHandle f)
{
#if DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_CONTIKI
	cfs_close(f);
	//return 1;
#elif DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_ARDUINO
	SD_File_Close(f);
    //return 1;
#else
	//return fclose(f);
	TEE_CloseObject(f);
#endif
}

void db_fileremove(char *filename, TEE_ObjectHandle table)
{
#if DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_CONTIKI
	//return (0==cfs_remove(filename));
#elif DB_CTCONF_SETTING_TARGET == DB_CTCONF_OPTION_TARGET_ARDUINO
	//return SD_File_Remove(filename);
#else
	if(table == NULL) {
		uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META;

		TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, filename, sizeof(int),
			flags, &table);
	}
	//return (0==remove(filename));
	TEE_CloseAndDeletePersistentObject1(table);
#endif
}
