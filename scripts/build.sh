#!/bin/bash


./configure --prefix=/usr/local/openresty --with-http_auth_request_module || exit 1

make -j4 || exit

make install


