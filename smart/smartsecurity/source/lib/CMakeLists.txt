##################################### PROJECT CMAKE SETUP START ####################################
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
##################################### PROJECT CMAKE SETUP END ######################################

################################### ARCH DEPENDENT START ###########################################
if (ARCH_ARM)
    INSTALL( DIRECTORY
             ../../internal/libcore
             ../../internal/libprimitive
             ../../internal/libtransport
             ../../internal/libprotocol
             ../../internal/libsfc
             ../../internal/libsfkc
             ../../internal/common
             DESTINATION "${INCLUDE_INSTALL_DIR}" FILES_MATCHING PATTERN "*.h" )
endif (ARCH_ARM)
################################### ARCH DEPENDENT END #############################################

########################## Add libraries to the build schedule START ###############################
ADD_SUBDIRECTORY(libcore)
ADD_SUBDIRECTORY(libprimitive)
ADD_SUBDIRECTORY(libprotocol)
ADD_SUBDIRECTORY(libtransport)
ADD_SUBDIRECTORY(libsfkc)
########################## Add libraries to the build schedule END #################################