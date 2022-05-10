#!/bin/bash

# curl -H"Referer: referer111" -w "%{http_code}" http://10.0.2.15:9999/request_uri_xxx


curl -H"Referer: referer111" -v  http://10.0.2.15:9999/request_uri_xxx
