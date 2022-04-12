#!/bin/bash

# wrk2实测延迟比wrk高一倍， wrk2工具不行
#wrk2 -t 5 -d 50s --latency -R500 http://localhost/
ulimit -n 65535

BIN=wrk
HOST=http://localhost:9999/

$BIN -t 1 -c 10000 -d 10s --latency $HOST

