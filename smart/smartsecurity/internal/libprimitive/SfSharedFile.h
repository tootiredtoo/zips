/**
****************************************************************************************************
* @vd_noapi
* @file SfSharedFile.h
* @brief Security framework [SF] class for sharing file
* @author Andrii Shelestov (a.shelestov)
* @date Created Sep 24, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12 
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#ifndef _SF_SHARED_FILE_H_
#define _SF_SHARED_FILE_H_

#include "libcore/SfTypes.h"

#include <string>
#include <cstdio>

class SfSharedFile
{
public:
    SfSharedFile();
    ~SfSharedFile();

    Bool isOpened() const;

    Bool open( const std::string& path, const char* mode );
    Bool reopen( const char* mode );

    size_t read( void* pBuffer, size_t byteCount );
    size_t write( const void* pBuffer, size_t byteCount );
    Bool seek( Int64 pos );
    Int64 tell();
    Uint64 size() const;
    Bool readFileContent( std::string& data );

    void close();

private:
    SfSharedFile( const SfSharedFile& );
    SfSharedFile& operator=( const SfSharedFile& );

    void calcFileSize();

private:
    FILE*       m_pFile;
    std::string m_filename;
    Uint64      m_size;
};

#endif  // _SF_SHARED_FILE_H_
