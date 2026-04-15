#CMAKE system version requirement
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

# Common for app/sfpmd and libprimitive definition:
ADD_DEFINITIONS(-DUSE_SIGACTION)

# Add project components to the build schedule
ADD_SUBDIRECTORY(lib)
ADD_SUBDIRECTORY(app)

IF(${BUILD_TESTS})
	ADD_SUBDIRECTORY(ut)
ENDIF()
