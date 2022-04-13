# fasthttp_hyperscan

fasthttp + hyperscan

## golang libs
+ tunny goroutine pool
+ govaluate : express compute
+ BODY:
    + 流式json解析： jsonparser gjson
    + xml解析
+ fasthttp: contain fasthttp goroutine pool
+ go-cache

## TODO
+ tunny协程池无法实现 每个协程对应独立的scratch
+ json config 解析 及 模块化
    + 移植 statbot mutl goroutine model
    + MainConfig module
    + RulesConfig : Match zone && regex && flag && logic
    + HSMatcher 模块化 
    + 实现规则引擎RuleEngine
    + 实现逻辑引擎LogicEngine(govaluate)
+ matcher 前面增加流式函数插件处理, 以及开关(spider_ip_rdns/router)
+ 原文匹配
+ 解码匹配
+ 自适应匹配
+ 协程池tunny实现对同一个matcher的匹配
+ 异步：通过通道传递数据到matcher的多个协程

## DONE
+ logrus + file-rotatelogs
+ fasthttp + hyperscan 
+ hyperscan static lib 
+ nginx性能测试 并发 + 延迟
+ fasthttp性能测试 并发 + 延迟
+ nginx + (http socket | unix socket)  + fasthttp 延迟测试

## hyperscan编译
+ hyperscan下载:https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/hyperscan/5.4.0-2/hyperscan_5.4.0.orig.tar.gz
+ boost下载: https://boostorg.jfrog.io/artifactory/main/release/1.69.0/source/boost_1_69_0.tar.gz
+ pcre 8.45下载: https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.bz2
+ 编译方法：
    + mkdir build && cd build
    + cmake .. -G Ninja -DBUILD_STATIC_LIBS=on
    + ninja && ninja install
    + go get -u -tags chimera github.com/flier/gohs/hyperscan

+ gohs使用
    + 需要指定hyerscan 安装的libhs.pc路径， libhs.pc文件包含库和头文件的路径, 默认安装到/usr/local/hyperscan
    + export PKG_CONFIG_PATH=/usrl/local/hyperscan

