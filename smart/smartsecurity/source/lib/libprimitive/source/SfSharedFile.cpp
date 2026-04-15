#include "SfSharedFile.h"
#include "libcore/SfDebug.h"

#include <vector>

#include <unistd.h>
#include <errno.h>
#include <sys/file.h>

//--------------------------------------------------------------------------------------------------

SfSharedFile::SfSharedFile()
    : m_pFile( NULL )
    , m_filename()
    , m_size( 0 )
{
}

//--------------------------------------------------------------------------------------------------

SfSharedFile::~SfSharedFile()
{
    close();
}

//--------------------------------------------------------------------------------------------------

Bool SfSharedFile::isOpened() const
{
    return ( m_pFile ) ? TRUE : FALSE;
}

//--------------------------------------------------------------------------------------------------

Bool SfSharedFile::open( const std::string& path, const char* mode )
{
    close();

    m_pFile = fopen( path.c_str(), mode );
    if ( !m_pFile )
    {
        SF_LOG_E( "Failed to open [%s] with mode [%s], error = [%s];",
                  path.c_str(), mode, SF_GET_SYSTEM_ERROR(errno) );
        return FALSE;
    }

    if ( flock( fileno( m_pFile ), LOCK_EX ) )
    {
        SF_LOG_E( "Failed to lock [%s], error = %s;", path.c_str(), SF_GET_SYSTEM_ERROR(errno) );
        fclose( m_pFile );
        m_pFile = NULL;
        return FALSE;
    }

    m_filename = path;
    calcFileSize();
    return TRUE;
}

//--------------------------------------------------------------------------------------------------

Bool SfSharedFile::reopen( const char* mode )
{
    m_pFile = freopen( m_filename.c_str(), mode, m_pFile );
    if ( !m_pFile )
    {
        SF_LOG_E( "Failed to open [%s] with mode [%s], error = [%s];",
                  m_filename.c_str(), mode, SF_GET_SYSTEM_ERROR(errno) );
        return FALSE;
    }

    calcFileSize();
    return TRUE;
}

//--------------------------------------------------------------------------------------------------

size_t SfSharedFile::read( void* pBuffer, size_t byteCount )
{
    if ( !m_pFile )
    {
        SF_LOG_E( "File is not opened;" );
        return 0;
    }
    return fread( pBuffer, 1, byteCount, m_pFile );
}

//--------------------------------------------------------------------------------------------------

size_t SfSharedFile::write( const void* pBuffer, size_t byteCount )
{
    if ( !m_pFile )
    {
        SF_LOG_E( "File is not opened;" );
        return 0;
    }
    return fwrite( pBuffer, 1, byteCount, m_pFile );
}

//--------------------------------------------------------------------------------------------------

Bool SfSharedFile::seek( Int64 pos )
{
    if ( !m_pFile )
    {
        SF_LOG_E( "File is not opened;" );
        return FALSE;
    }

    return ( fseek( m_pFile, pos, SEEK_SET ) == 0 ) ? TRUE : FALSE;
}

//--------------------------------------------------------------------------------------------------

Int64 SfSharedFile::tell()
{
    if ( !m_pFile )
    {
        SF_LOG_E( "File is not opened;" );
        return -1;
    }

    return ftell( m_pFile );
}

//--------------------------------------------------------------------------------------------------

Uint64 SfSharedFile::size() const
{
    return m_size;
}

//--------------------------------------------------------------------------------------------------

Bool SfSharedFile::readFileContent( std::string& data )
{
    typedef std::vector< Uint8 > ByteVector;

    ByteVector bv( m_size + 1, 0 );
    if ( read( &bv[ 0 ], m_size ) == m_size )
    {
        data = (char*)( &bv[ 0 ] );
        return TRUE;
    }
    return FALSE;
}

//--------------------------------------------------------------------------------------------------

void SfSharedFile::close()
{
    if ( m_pFile )
    {
        Int fd = fileno( m_pFile );
        fflush( m_pFile );
        fsync( fd );
        flock( fd, LOCK_UN );
        fclose( m_pFile );
        m_pFile = NULL;
    }

    m_size = 0;
    m_filename.clear();
}

//--------------------------------------------------------------------------------------------------

void SfSharedFile::calcFileSize()
{
    fseek( m_pFile, 0, SEEK_END );
    long fsize = 0;
    fsize = ftell( m_pFile );
    if (fsize > 0)
    {
        m_size = (Uint64)(unsigned long)fsize;
    }
    else
    {
        m_size = 0;
    }
    fseek( m_pFile, 0, SEEK_SET );
}

//--------------------------------------------------------------------------------------------------
