# fasthttp_hyperscan
fasthttp + hyperscan

# TODO
+ hyperscan static lib 
+ fasthttp + hyperscan 
+ config

# DONE
+ nginx性能测试 并发 + 延迟
+ fasthttp性能测试 并发 + 延迟
+ nginx + (http socket | unix socket)  + fasthttp 延迟测试

# hyperscan编译
+ hyperscan下载:https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/hyperscan/5.4.0-2/hyperscan_5.4.0.orig.tar.gz
+ boost下载: https://boostorg.jfrog.io/artifactory/main/release/1.69.0/source/boost_1_69_0.tar.gz
+ pcre 8.45下载: https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.bz2
+ 编译方法：
    + mkdir build && cd build
    + cmake .. -G Ninja -DBUILD_STATIC_LIBS=on
    + ninja && ninja install
    + go get -u -tags chimera github.com/flier/gohs/hyperscan
