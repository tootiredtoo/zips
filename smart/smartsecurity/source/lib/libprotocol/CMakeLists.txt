##################################### PROJECT CMAKE SETUP START ####################################
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(libprotocol C)
##################################### PROJECT CMAKE SETUP END ######################################
INCLUDE( FindPkgConfig )
pkg_check_modules( dlog REQUIRED dlog )

SET(SF_LIBPROTOCOL_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/source/")
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/internal ${CMAKE_SOURCE_DIR}/internal/libprotocol/
                    ${dlog_INCLUDE_DIRS})

FILE(GLOB_RECURSE SF_LIBPROTOCOL_SRC "${SF_LIBPROTOCOL_SRC_DIR}/*.c")
ADD_DEFINITIONS(-DUS_MODULE -DSF_TRANSPORT_NETLINK -DSF_BIN_TAG=\"${PROJECT_NAME}\" )
ADD_LIBRARY(protocol SHARED ${SF_LIBPROTOCOL_SRC})
INSTALL( TARGETS protocol LIBRARY DESTINATION ${LIB_INSTALL_DIR})
