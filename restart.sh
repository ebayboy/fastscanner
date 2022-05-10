#!/bin/bash

go build || exit 1

./fastscanner -d
