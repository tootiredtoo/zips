cmake_minimum_required( VERSION 2.8 )

project( AppSfcUse CXX )

set ( APP_ROOT_DIR "../../../../" )
set ( APP_INCLUDE_DIR ${APP_ROOT_DIR}/include )
set ( APP_THIRD_PARTY_LIB_DIR ${APP_ROOT_DIR}../../lib/third_party )
set ( APP_INCLUDE_THIRD_PARTY ${APP_ROOT_DIR}/third_party/cppunit/include )
set ( APP_LIB_DEST ${APP_ROOT_DIR}/lib/cmake )
set ( APP_BIN_DEST ${APP_ROOT_DIR}../../bin/cmake )

set ( SF_LIBSFC_APP_INCLUDE_DIR ${APP_ROOT_DIR}/source/ut/app/app_sfc_use/include )
set ( SF_LIBSFC_APP_SOURCE_DIR ${APP_ROOT_DIR}/source/ut/app/app_sfc_use/source )

cmake_policy(SET CMP0015 OLD)
LINK_DIRECTORIES(${SF_PROJECT_DIR}/lib/third_party/ ${SF_PROJECT_DIR}/lib/cmake)

add_definitions( -Wall )
add_definitions( -DDEBUG_BUILD -DUS_MODULE -DSF_TRANSPORT_NETLINK )

set( CMAKE_EXE_LINKER_FLAGS "-Wl,-rpath,\$ORIGIN -Wl,-rpath,\$ORIGIN/../../../../lib/cmake" )

include_directories( ${APP_INCLUDE_THIRD_PARTY} )
include_directories( ${APP_INCLUDE_DIR} )
include_directories( ${SF_LIBSFC_APP_INCLUDE_DIR} )

FILE(GLOB SFC_USE_APP_SOURCE "${SF_LIBSFC_APP_SOURCE_DIR}/*.cpp")

add_executable( AppSfcUse ${SFC_USE_APP_SOURCE} )

if(ARCH_ARM)
    install( TARGETS AppSfcUse RUNTIME DESTINATION ${TZ_SYS_BIN} )
    target_link_libraries( AppSfcUse core ${dlog_LIBRARIES})
else(ARCH_ARM)
    target_link_libraries( AppSfcUse core rt )
endif(ARCH_ARM)

