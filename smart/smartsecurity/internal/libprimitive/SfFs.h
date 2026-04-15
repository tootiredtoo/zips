/**
****************************************************************************************************
* @vd_noapi
* @file SfFs.h
* @brief Security framework [SF] Functions declaration to manipulate with file system
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @date Created Nov 18, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_FS_H_
#define _SF_FS_H_

#include "libcore/SfCore.h"

#include <string>
#include <vector>
#include <list>
#include <cstdio>
#include <stdexcept>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/**
****************************************************************************************************
* @brief Write
****************************************************************************************************
*/
typedef std::list< std::string > SfFilesList;
typedef std::vector< std::string > PathList;
typedef void (*callback_file_count)(Int64 cnt);

enum ECReturn
{
    ECR_CONTINUE,
    ECR_STOP
};

enum EntryType
{
    ET_FILE,
    ET_FOLDER,
    ET_CHARDEV,
    ET_BLOCKDEV,
    ET_PIPE,
    ET_LINK,
    ET_SOCKET,
    ET_UNKNOWN
};

typedef ECReturn (*EntryCallback)( const std::string& entry, void* pArg );


/**
****************************************************************************************************
* @brief                    return total count of regular files by using callback(recursive)
* @param [in] path          Path to the folder
* @param [in] callback      Callback function pointer
* @param [in] total         Previous file count.
* @return                   Files count
****************************************************************************************************
*/
Uint64 CountFilesRecursiveRetCnt( const std::string& path, callback_file_count callback, Uint64& total, int& bStopDigit );

Uint64 GetDirectoryFlashUsage(const std::string& dirPath);

/**
****************************************************************************************************
* @brief                    Get list of regular files and subfolders in given folder(non-recursive)
* @param [in] path          Path to the folder
* @param [in,out] files     List of the regular files (including parent path)
* @param [in,out] folders   List of the subfolders(including parent path) with ending slash
* @return                   TRUE on success
****************************************************************************************************
*/
Bool ListFolderContent( const std::string& path, SfFilesList& files, SfFilesList& folders );

/**
****************************************************************************************************
* @brief					Delete file
* @param [in] file			File name
* @return					True if file was deleted, false otherwise
****************************************************************************************************
*/
bool DeleteFile( const std::string& file );

/**
****************************************************************************************************
* @brief Write
****************************************************************************************************
*/
bool RenameFile( const std::string& file, const std::string& newName );

/**
****************************************************************************************************
* @brief					Check whether file exists (tries to open for reading)
* @param [in] file			File name
* @return					True if file exists, false otherwise
****************************************************************************************************
*/
bool FileExists( const std::string& file );

/**
****************************************************************************************************
* @brief						Check whether folder exists (is actually a folder)
* @param [in] folder			Path to folder
* @return						True if folder exists, false otherwise
****************************************************************************************************
*/
bool FolderExists( const std::string& folder );

/**
****************************************************************************************************
* @brief Write
****************************************************************************************************
*/
bool CreateFolder( const std::string& folder );

/**
****************************************************************************************************
* @brief Creating Full Path
****************************************************************************************************
*/
bool CreateFullPathFolder( const std::string& folder );

/**
****************************************************************************************************
* @brief Write
****************************************************************************************************
*/
bool CopyFile( const std::string& src, const std::string& dest );

/**
****************************************************************************************************
* @brief					Get absolute pathame (expand all symbolic links)
* @param [in] path			Path to canonicalize
* @return					Absolute path or empty string on error
****************************************************************************************************
*/
std::string GetAbsolutePath( const std::string& path );

/**
****************************************************************************************************
* @brief					Get Filename
* @param [in] path			file's path
* @return					return Filename(std::string)
****************************************************************************************************
*/
std::string  FindFileNameFromPath( const std::string& path );

/**
****************************************************************************************************
* @brief					Set whether urgent-esacpe needs.
* @param [in] value			TRUE or FALSE; if TRUE, urgent-escape will be processed.
* @return					return void
****************************************************************************************************
*/
void SetUrgentEscapeScan(Bool value);

Bool GetUrgentEscapeScan();

/**
****************************************************************************************************
* @brief                    IsProcFs
* @param [in]  fileName     File Name
* @return                   TRUE if success, FALSE otherwise
****************************************************************************************************
*/
bool IsProcFs( const std::string& fileName);

/**
****************************************************************************************************
* @brief                    readProcFsFile
* @param [in]  fileName     File Name
* @param [out] message      process content
* @param [in]  limit        File Size Limit
* @return                   TRUE if success, FALSE otherwise
****************************************************************************************************
*/
bool readProcFsFile( const std::string& fileName, std::string& message, const size_t limit );

/**
****************************************************************************************************
* @brief                    readRegualarFile
* @param [in]  fileName     File Name
* @param [in]  fileStatus   File Status
* @param [out] content      File Content
* @param [in]  limit        File Size Limit
* @param [in]  SendFileFlag Report Flag
* @return                   TRUE if success, FALSE otherwise
****************************************************************************************************
*/
bool readRegularFile( const std::string & fileName, struct stat & fileStatus, std::vector<uint8_t> & content, const size_t limit, const int SendFileFlag );

/**
****************************************************************************************************
* @brief                    check if the file is symbolic link.
* @param [in]  pszFilePath  File Path
* @return                   true if symbolic link, false otherwise
****************************************************************************************************
*/
bool IsSymbolic(const std::string& FilePath);

/**
****************************************************************************************************
* @brief                    Get file size
* @param [in]  filename     file full path           
* @return                   file size
****************************************************************************************************
*/
long GetFileSizeFromPath(const char* filename);

/**
****************************************************************************************************
* @brief                    synchronize a file's in-core state with storage device
* @param [in]  pFile        FILE pointer
* @return                   void
****************************************************************************************************
*/
void FileFsync(FILE* pFile);

int ClearDirectory(const char *directory);

#endif /* !_SF_FS_H_ */
