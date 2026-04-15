#CMAKE system version requirement
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

# Add project components to the build schedule
ADD_SUBDIRECTORY(libcore)
ADD_SUBDIRECTORY(libsfc)
ADD_SUBDIRECTORY(libprimitive)
ADD_SUBDIRECTORY(libprotocol)
