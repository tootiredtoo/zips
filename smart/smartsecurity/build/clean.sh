
#!/bin/bash

NS_ROOT_DIR=`pwd`/..

function clean
{
    rm -rf `find . -type d -name "CMakeFiles"` > /dev/null
    rm -rf `find . -type f -name "CMakeCache.txt"` > /dev/null
    rm -rf `find . -type f -name "cmake_install.cmake"` > /dev/null
    rm -rf `find . -type f -name "*.o"` > /dev/null
    rm -rf `find . -type f -name "*.ko"` > /dev/null
    rm -rf `find . -type f -name "*.mod.c"` > /dev/null
    rm -rf `find . -type f -name "*.symvers"` > /dev/null
    rm -rf `find . -type f -name "*.order"` > /dev/null
    rm -rf `find . -type f -name "*.pro.user"` > /dev/null
    rm -rf `find . -type f -name "Makefile" ! -path "./mod/Makefile"` > /dev/null
    rm -rf ${NS_ROOT_DIR}/lib/cmake ${NS_ROOT_DIR}/bin ${NS_ROOT_DIR}/build/source > /dev/null
}

clean
cd ${NS_ROOT_DIR}/source
clean
echo "Done;"
