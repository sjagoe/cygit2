#!/bin/sh

set -e
set -x

git clone https://github.com/libgit2/libgit2.git
cd libgit2
mkdir build
cd build
cmake ..
cmake --build .
