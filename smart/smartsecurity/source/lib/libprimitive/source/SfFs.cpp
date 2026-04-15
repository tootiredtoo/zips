/**
****************************************************************************************************
* @file SfFs.cpp
* @brief Security framework [SF] Functions implementation to manipulate with file system
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @date Created Nov 18, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#include "SfFs.h"
#include "libcore/SfDebug.h"

#include <fstream>
#include <cstdio>

#if defined(SF_OS_WINDOWS)
    #include <direct.h>
    #include <windows.h>
#else
    #include <dirent.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #include <limits.h>
    #include <cstdlib>
    #include <mutex>
#endif /* !SF_OS_WINDOWS */

static Bool sf_urgent_escape = FALSE;
static std::mutex sf_urgent_escape_mutex;

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static void FixPath( std::string& path )
{
    if ( !path.empty() ) {
        while ( !path.empty() && ( *path.rbegin() == '/' ) )
            path = path.substr( 0, path.size() - 1 );
        path.append( "/" );
    }
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static EntryType GetEntryTypeStat( const std::string& fullName )
{
    struct stat entStat;
    if ( stat( fullName.c_str(), &entStat ) == -1 )
    {
        return ET_UNKNOWN;
    }

    EntryType type = ET_UNKNOWN;
    switch ( entStat.st_mode & S_IFMT )
    {
        case S_IFDIR:  type = ET_FOLDER;   break;
        case S_IFREG:  type = ET_FILE;     break;
        case S_IFBLK:  type = ET_BLOCKDEV; break;
        case S_IFCHR:  type = ET_CHARDEV;  break;
        case S_IFIFO:  type = ET_PIPE;     break;
        case S_IFLNK:  type = ET_LINK;     break;
        case S_IFSOCK: type = ET_SOCKET;   break;
        default:       type = ET_UNKNOWN;  break;
    }
    return type;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static EntryType GetEntryType( const dirent* pEntry, const std::string& fullName )
{
    EntryType type = ET_UNKNOWN;
    switch ( pEntry->d_type )
    {
        case DT_DIR:     type = ET_FOLDER;                    break;
        case DT_REG:     type = ET_FILE;                      break;
        case DT_BLK:     type = ET_BLOCKDEV;                  break;
        case DT_CHR:     type = ET_CHARDEV;                   break;
        case DT_FIFO:    type = ET_PIPE;                      break;
        case DT_LNK:     type = ET_LINK;                      break;
        case DT_SOCK:    type = ET_SOCKET;                    break;
        case DT_UNKNOWN: type = GetEntryTypeStat( fullName ); break;
        default:         type = ET_UNKNOWN;                   break;
    }
    return type;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static Uint32 GetDirentLength( DIR* pDir )
{
    Uint32 length = 0;
    Long pcNameMax = fpathconf( dirfd( pDir ), _PC_NAME_MAX );
    if ( -1 == pcNameMax )
        length = 8 * 1024; // failed to get config value, just guess something large enough
    else
        length = (unsigned long)(offsetof( struct dirent, d_name ) + pcNameMax + 1);
    return length;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static Bool GetFolderContent( const std::string& path, SfFilesList& files, SfFilesList& folders,
                              Bool getFiles, Bool getFolders, Uint32& fiCount, Uint32& foCount )
{
    Bool r = FALSE;

    if ( getFiles )   files.clear();
    if ( getFolders ) folders.clear();
    fiCount = 0; foCount = 0;

    if (sf_urgent_escape == TRUE) {
        return FALSE;
    }
    DIR* pDir = opendir( path.c_str() );
    if ( pDir ) {
        if (sf_urgent_escape == TRUE) {
            closedir( pDir );
            return FALSE;
        }
        
        dirent* pEntry = NULL, *pDirEntry = (dirent*)malloc( GetDirentLength( pDir ) );
        if ( !pDirEntry )
        {
            SF_LOG_E( "Failed to allocate;" );
            closedir( pDir );
            return FALSE;
        }
        // Because of CPU Scheduling added sleep.
        SfSleepMs(1);
        //////////////////////////////////////
        while ( !readdir_r( pDir, pDirEntry, &pEntry ) && ( pEntry != NULL ) ) 
        {
            if (sf_urgent_escape == TRUE) {
                break;
            }
            std::string entryName = pEntry->d_name;
            if ( entryName.empty() || entryName == "." || entryName == ".." )
                continue;

            entryName = path + entryName;
            EntryType type = GetEntryType( pEntry, entryName );
            if ( ET_FILE == type ) {
                ++fiCount;
                if ( getFiles ) files.push_back( entryName );
            }
            if ( ET_FOLDER == type ) {
                ++foCount;
                if ( getFolders ) folders.push_back( entryName + "/" );
            }
        } /* end while */
        free( pDirEntry );
        malloc_trim(0);
        closedir( pDir );
        r = TRUE;
    }
    return r;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Uint64 CountFilesRecursiveRetCnt( const std::string& path, callback_file_count callback, Uint64& total, int& bStopDigit )
{
    std::string cPath = path;
    FixPath( cPath );

    Uint64 res = 0;
    SfFilesList foldersList;
    foldersList.push_back( cPath );
    while ( !foldersList.empty() ) {
        if (sf_urgent_escape== TRUE) {
            return 0;
        }
        if ( bStopDigit == 1 )
        {
            SF_LOG_I( "stop noti;" );
            return 0;
        }
        std::string currFld = foldersList.back();
        foldersList.pop_back();

        SfFilesList lFiles, lFolders;
        Uint32 fiCount = 0, foCount = 0;
        if ( GetFolderContent( currFld, lFiles, lFolders, FALSE, TRUE, fiCount, foCount ) ) {
            foldersList.splice( foldersList.end(), lFolders );
            res += Uint64( fiCount );
            if (callback)
            {
                callback(total + res);
            }
        }
    }
    return res;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static Bool GetDirectorySize(const std::string& path, SfFilesList& files, SfFilesList& folders, Uint64& directorySize)
{
    files.clear();
    folders.clear();
    directorySize = 0;

    DIR* pDir = opendir(path.c_str());
    if (pDir) {
        dirent *pDirEntry = (dirent*)malloc(GetDirentLength(pDir));
        if (!pDirEntry) {
            SF_LOG_E("Failed to allocate;");
            closedir(pDir);
            return FALSE;
        }
        SfSleepMs(1);

        int accessCount = 0;
        dirent *pEntry = NULL;
        while (!readdir_r(pDir, pDirEntry, &pEntry) && (pEntry != NULL)) {
            if (++accessCount % 5000 == 0) {
                sleep(1);
            }

            std::string entryName = pEntry->d_name;
            if (entryName.empty() || entryName == "." || entryName == "..") {
                continue;
            }

            entryName = path + entryName;
            EntryType type = GetEntryType(pEntry, entryName);
            if (ET_FILE == type) {
                Uint64 fileSize = static_cast<unsigned int>(GetFileSizeFromPath(entryName.c_str()));
                directorySize += fileSize;
            }
            else if (ET_FOLDER == type) {
                folders.push_back(entryName + "/");
            }
        }
        free(pDirEntry);
        malloc_trim(0);
        closedir(pDir);
    }
    return TRUE;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Uint64 GetDirectoryFlashUsage(const std::string& dirPath)
{
    std::string cPath = dirPath;
    FixPath(cPath);

    Uint64 totalSize = 0;
    SfFilesList foldersList;
    foldersList.push_back(cPath);
    while (!foldersList.empty()) {
        std::string currFld = foldersList.back();
        foldersList.pop_back();

        SfFilesList lFiles;
        SfFilesList lFolders;
        Uint64 directorySize = 0;
        if (GetDirectorySize(currFld, lFiles, lFolders, directorySize) ) {
            foldersList.splice(foldersList.end(), lFolders);
            totalSize += directorySize;
        }
    }
    return totalSize;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Bool ListFolderContent( const std::string& path, SfFilesList& files, SfFilesList& folders )
{
    std::string cPath = path;
    FixPath( cPath );

    Uint32 fiCount = 0, foCount = 0;
    return GetFolderContent( cPath, files, folders, TRUE, TRUE, fiCount, foCount );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
bool DeleteFile( const std::string& file )
{
    return ( unlink( file.c_str() ) == 0 );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
bool RenameFile( const std::string& file , const std::string& newName )
{
    return ( rename( file.c_str(), newName.c_str() ) == 0 );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
bool FileExists( const std::string& file )
{
    std::ifstream istream( file.c_str() );
    return !istream.fail();
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
bool FolderExists( const std::string& folder )
{
#if defined(SF_WINDOWS)
    DWORD fileAttr = GetFileAttributesA( folder.c_str() );
    if ( fileAttr == INVALID_FILE_ATTRIBUTES )
        return false;
    else
        return ( fileAttr & FILE_ATTRIBUTE_DIRECTORY );
#else
    struct stat statCtx;
    if ( ( ::stat( folder.c_str(), &statCtx ) == 0 ) && S_ISDIR( statCtx.st_mode ) )
        return true;
    else
        return false;
#endif // SF_WINDOWS
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
bool CreateFolder( const std::string& folder )
{
#if defined(SF_WINDOWS)
    return ( _mkdir( folder.c_str() ) == 0 );
#else
    return ( mkdir( folder.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH ) == 0 );
#endif // SF_WINDOWS
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
bool CreateFullPathFolder( const std::string& folder )
{
#if defined(SF_WINDOWS)
    return ( _mkdir( folder.c_str() ) == 0 );
#else
    #define FORCE_DIRC_BUFF     1024
    
    char    buff[FORCE_DIRC_BUFF + 1] = {0};
    char   *p_dirc  = NULL;

    SF_LOG_I("%s;", folder.c_str());    
    snprintf(buff, FORCE_DIRC_BUFF, "%s", folder.c_str());
    p_dirc = buff;
    
    if (*p_dirc != '/')
    {
        return false;
    }
    if (buff[folder.size()] == '/')
    {
        buff[folder.size()] = 0x00;
    }
    p_dirc++;
    while(*p_dirc)
    {
        if (*p_dirc == '/')
        {
            *p_dirc = '\0';
            //SF_LOG_I("[buff : %s];", buff);
            if (FolderExists(std::string(buff)) == false)
            {
                if (CreateFolder(std::string(buff)) == false)
                {
                    return false;
                }
            }
            *p_dirc = '/';
        }
        p_dirc++;
    } /* end while */
    SF_LOG_I("[%s];", buff);
    if (FolderExists(std::string(buff)) == false)
    {
        if (CreateFolder(std::string(buff)) == false)
        {
            return false;
        }
    }
    return true;
#endif // SF_WINDOWS
}


/*
****************************************************************************************************
*
****************************************************************************************************
*/
bool CopyFile( const std::string& src, const std::string& dest )
{
    std::ifstream srcStream( src.c_str(), std::ios_base::binary );
    if ( !srcStream )
        return false;

    std::ofstream destStream( dest.c_str(), std::ios_base::binary );
    if ( !destStream )
        return false;

    destStream << srcStream.rdbuf() << std::flush;
    sync();
    return !destStream.fail();
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
std::string GetAbsolutePath( const std::string& path )
{
#if defined(SF_WINDOWS)
#else
    char *pBuf = realpath( path.c_str(), NULL );
    std::string rReturn;
    if (pBuf)
    {
        rReturn = std::string(pBuf);
        free(pBuf);
    }
    return rReturn;
#endif // SF_WINDOWS
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
std::string FindFileNameFromPath( const std::string& path )
{
    std::string rResult;
    if (!path.empty())
    {
        std::size_t found  = path.find_last_of("/");
        if (std::string::npos != found)
        {
            rResult = path.substr(found + 1);
        }
    }
    return rResult;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SetUrgentEscapeScan(Bool value)
{
    std::lock_guard<std::mutex> mtxGuard(sf_urgent_escape_mutex);
    sf_urgent_escape = value;
}

Bool GetUrgentEscapeScan()
{
    std::lock_guard<std::mutex> mtxGuard(sf_urgent_escape_mutex);
    return sf_urgent_escape;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
bool IsProcFs(const std::string& fileName)
{
    return (0 == fileName.find("/proc/"));
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
bool readProcFsFile(const std::string& fileName, std::string& message, const size_t limit )
{
     bool result=false;
    try
    {
        std::fstream file;
        file.open(fileName.c_str(), std::ios_base::in);
        if (file.is_open())
        {
            message.clear();
            while (file.good() and not file.eof())
            {
                char c;
                file >> std::noskipws >> c;
                message.push_back(c);
                if (limit < message.size())
                {
                    file.close();
                    throw(std::overflow_error("PROCFS OVERLIMIT"));
                }
            }
            result = file.eof();
            file.close();
        }
        else
        {
            SF_LOG_E("[Open Error : %s]", fileName.c_str());
        }
    }
    catch (const std::exception & e)
    {
        SF_LOG_E("[Exception Error : %s]", fileName.c_str());
    }
    return result;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
bool readRegularFile(const std::string & fileName, struct stat & fileStatus, std::vector<uint8_t> & content, const size_t limit, const int SendFileFlag)
{
    try {
        if (::stat(fileName.c_str(), &fileStatus) != 0) {
            throw std::runtime_error(std::string("StatErr : " + fileName));
        }

        std::ifstream file(fileName.c_str(), std::ios::binary | std::ios::in | std::ios::ate);
        if (file.is_open() != true) {
            throw std::runtime_error(std::string("OpenErr : " + fileName));
        }

        const size_t fileSize = file.tellg();
        if (limit < fileSize) {
            file.close();
            throw std::overflow_error("REGULAR OVERLIMIT");
        }

        file.seekg(0, std::ios::beg);
        content.resize(fileSize);
        file.read(reinterpret_cast<char *>(content.data()), std::streamsize(fileSize));
        file.close();
        return true;
    }
    catch (const std::exception& e) {
        SF_LOG_E("[Exception Error : %s]", e.what());
        return false;
    }
}

/**
****************************************************************************************************
* check whether file is symbolic file
****************************************************************************************************
*/
bool IsSymbolic(const std::string& FilePath)
{
    struct stat file_status;
    
    if (lstat(FilePath.c_str(), &file_status) == 0)
    {
        if ((file_status.st_mode & S_IFMT) == S_IFLNK)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    return false;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
long GetFileSizeFromPath(const char* filename)
{
    std::ifstream in( filename, std::ifstream::binary | std::ifstream::ate);
    return in.tellg(); 
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
void FileFsync(FILE* pFile)
{
    int fd = -1;
    
    if (pFile)
    {
        fd = fileno(pFile);
        if (fd != -1)
        {
            if (fsync(fd) != 0)
            {
                SF_LOG_E( "sync failed[%d];", errno );
            }
        }
        else
        {
            SF_LOG_E( "failed[%d];", errno );
        }
    }
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
int ClearDirectory(const char *directory)
{
    SF_LOG_I("directory : %s", directory);
    
    const std::string& reportBaseDir = directory;
    SfFilesList subDir;
    SfFilesList datafiles;
    datafiles.clear();
    subDir.clear();

    if (!ListFolderContent(reportBaseDir, datafiles, subDir)) {
        SF_LOG_E("Fail to list up files in directory ;");
    }

    int datafileSize = datafiles.size();
    SF_LOG_I("Files count : %d", datafileSize);

    for (auto filename : datafiles) {
        if (!DeleteFile(filename)) {
            SF_LOG_W("Fail to delete file : %s",filename.c_str());
            continue;
        }
        
        datafileSize--;
        if (datafileSize % 5000 == 0) {
            sleep(2);
        }
    }
    SF_LOG_I("Clear Files count : %d", datafileSize);
    return datafileSize;
}
