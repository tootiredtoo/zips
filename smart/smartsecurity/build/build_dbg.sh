
#!/bin/bash

ROOT_DIR=`pwd`/../

function unzip_libnl
{
    cd ${ROOT_DIR}/third_party/
    rm -rf libnl/
    tar xf libnl-3.2.22.tar.gz
    mv libnl-3.2.22 libnl
    cd -
}

function unzip_ccore
{
    cd ${ROOT_DIR}/third_party/
    rm -rf CryptoCore/
    tar xf CryptoCore_v0.1.24.1.tar.gz
    mv CryptoCore_v0.1.24.1/ CryptoCore/
    cd -
}

ARCH=`uname -i`
if [[ ${ARCH} == i386 ]]; then
    ARCH=X86
elif [[ ${ARCH} == x86_64 ]]; then
    ARCH=X86_64
else
    echo "unknown arch; exit..."
    exit -1
fi

unzip_libnl
unzip_ccore
cmake .. -DARCH_${ARCH}=TRUE -DDEBUG_BUILD=TRUE
make -j8