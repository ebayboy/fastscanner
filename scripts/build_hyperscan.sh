
rm -rf build
mkdir build && cd build
cmake -DBUILD_STATIC_LIBS=on -DCMAKE_BUILD_TYPE=Release  ..
make -j4
