/**
****************************************************************************************************
* @vd_noapi
* @file UnixSocket.h
* @brief Security framework [SF] class for Unix Socket
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com), Anton Skakun (a.skakun@samsung.com)
* @date Created Jun 5, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#pragma once
#ifndef _UNIX_SOCKET_H_
#define _UNIX_SOCKET_H_

#include "libcore/SfCore.h"

#include <string>
#include <sys/un.h>
#include <limits.h>

class UnixSocket
{
public: // func
    UnixSocket();
    ~UnixSocket();

    /**
    ************************************************************************************************
    * @brief                        Setup socket to accept incoming connections ( binds name to address )
    * @param [in] hostName          Name of the socket to be created
    * @param [in] maxConnections    Maximum number of incoming connections to be handled
    * @return                       SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS SetupHost( const char* hostName, Uint32 maxConnections );

    /**
    ************************************************************************************************
    * @brief                        Accept incoming connection from remote socket
    * @param [in] remoteSocket      Remote socket( will be filled with correct values from remote side )
    * @return                       SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS AcceptConnection( UnixSocket& remoteSocket );

    /**
    ************************************************************************************************
    * @brief                        Accept incoming connection from remote socket om nonblocked socket
    * @param [in/out] remoteSocket  Remote socket( will be filled with correct values from remote side )
    * @param [in] msec              timeout for accept conection
    * @param [in] silent            if TRUE then message will not show
    * @return                       SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS AcceptConnection( UnixSocket& remoteSocket, Uint32 msec, Bool silent );

    /**
    ************************************************************************************************
    * @brief                        Connect to remote socket by its name
    * @param [in] remoteHostName    Name of the socket to connect
    * @return                       SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS ConnectToHost(const char* remoteHostName);
    SF_STATUS ConnectToHostNonBlocking(const char* remoteHostName);

    /**
    ************************************************************************************************
    * @brief                        Disconnect. Closes socket file descriptor
    * @return                       SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS Disconnect();

    /**
    ************************************************************************************************
    * @brief                        setNonBlocking. Mark socket as nonblocking
    * @return                       SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS SetNonBlocking();

    /**
    ************************************************************************************************
    * @brief                        Is valid (greater then 0) descriptor
    * @return                       TRUE on success, FALSE otherwise
    ************************************************************************************************
    */
    Bool IsConnected() const;

    /**
    ************************************************************************************************
    * @brief                        send string to client
    * @return                       TRUE on success, FALSE otherwise
    ************************************************************************************************
    */
    Bool SendString( const std::string& message );

    /**
    ************************************************************************************************
    * @brief                        receive string from client
    * @return                       TRUE on success, FALSE otherwise
    ************************************************************************************************
    */
    Bool ReceiveString( std::string& message );

    /**
    ************************************************************************************************
    * @brief                        receive string from client with timeout in millisecond
    * @return                       TRUE on success, FALSE otherwise
    ************************************************************************************************
    */
    Bool ReceiveString( std::string& message, Uint32 msec );
    
    /**
    ************************************************************************************************
    * @brief                        Check whether socket is ready for reading with timeout
    * @param [in] msec              Timeout in milliseconds
    * @return                       TRUE on success, FALSE otherwise
    ************************************************************************************************
    */
    Bool IsReadyForReading( Uint32 msec ) const;

    /**
    ************************************************************************************************
    * @brief                        Check whether socket is ready for writing with timeout
    * @param [in] msec              Timeout in milliseconds
    * @return                       True if socket is ready, false otherwise
    ************************************************************************************************
    */
    Bool IsReadyForWriting( Uint32 msec ) const;

private: // func
    UnixSocket( const UnixSocket& );                    // blocked
    const UnixSocket& operator=( const UnixSocket& );   // blocked

    /**
    ************************************************************************************************
    * @brief                        Binds socket file descriptor to its name
    * @return                       SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS Bind();

    /**
    ************************************************************************************************
    * @brief                        Prepares socket to accept connections on its file descriptor
    * @param [in] maxConnections    Maximum number of incoming connections
    * @return                       SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS Listen( Uint32 maxConnections );

    /**
    ************************************************************************************************
    * @brief                        Prepares socket internal structure
    * @param [in] socketName        Socket name to be assigned
    * @return
    ************************************************************************************************
    */
    void SetupSocket( const char* socketName );

    Bool SendData( const Uint8* data, Uint32 length );

    Bool ReceiveData( Uint8* data, Uint32 length );

    /**
    ************************************************************************************************
    * @brief                        Generates socket file descriptor
    * @return                       SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS CreateSocketDescriptor();

public: // var
    static const Int32  s_badDescriptor;

private: // var
    Int32           m_socketDescriptor;
    sockaddr_un     m_socketStruct;

}; // class UnixSocket

#endif // _UNIX_SOCKET_H_
