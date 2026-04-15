##################################### PROJECT CMAKE SETUP START ####################################
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(libtransport C)
##################################### PROJECT CMAKE SETUP END ######################################
INCLUDE( FindPkgConfig )
pkg_check_modules( dlog REQUIRED dlog )
pkg_check_modules( libnl-3.0 REQUIRED libnl-3.0 )

SET(SF_LIBTRANSPORT_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/source/")
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/internal ${CMAKE_SOURCE_DIR}/internal/libtransport/
                    ${CMAKE_SOURCE_DIR}/source/lib/libtransport/include/ ${dlog_INCLUDE_DIRS}
                    ${libnl-3.0_INCLUDE_DIRS})

FILE(GLOB_RECURSE SF_LIBTRANSPORT_SRC "${SF_LIBTRANSPORT_SRC_DIR}/*.c")
LIST(REMOVE_ITEM SF_LIBTRANSPORT_SRC "${SF_LIBTRANSPORT_SRC_DIR}/netlink/SfNetlinkKernel.c")

ADD_DEFINITIONS(-DUS_MODULE -DSF_TRANSPORT_NETLINK -DSF_BIN_TAG=\"${PROJECT_NAME}\")
ADD_LIBRARY(transport SHARED ${SF_LIBTRANSPORT_SRC} )
TARGET_LINK_LIBRARIES(transport core protocol  ${libnl-3.0_LIBRARIES})
INSTALL( TARGETS transport LIBRARY DESTINATION ${LIB_INSTALL_DIR})
