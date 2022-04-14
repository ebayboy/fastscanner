#!/bin/bash -x

if [ ! -d "/usrl/local/hyperscan" ];then
    tar xvf libs/hyperscan.tar.bz2  -C ./libs/
    cp -afR ./libs/hyperscan /usr/local/ 
    export PKG_CONFIG_PATH=/usrl/local/hyperscan
fi

go build
