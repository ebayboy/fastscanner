#!/bin/bash

wrk -t5 -d10s --latency  http://10.0.2.15:9999/
