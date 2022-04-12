#!/bin/bash

cp -afR ./libs/hyperscan /usr/local/ 
export PKG_CONFIG_PATH=/usrl/local/hyperscan
go build
