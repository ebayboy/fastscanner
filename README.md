# fasthttp_hyperscan

fasthttp + hyperscan

## Loglevel

## Usage:
- 如果 -unix "", 则使用 -addr 启动服务

## 架构 + Data flow: dist_worker -> scan_worker -> scanners -> matchers
+ 一共有N个不同的matcher, 一个matcher对应一组规则,
+ 命中结果集输出:
referer
    "results": [
    {
        "mz": "$request_uri",
        "rules" :[
        {
            "id": "1001",
            "from": 0,
            "to": 10
        },
        {
            "id": "1002",
            "from": 0,
            "to": 10
        }
        ]
    },
    {
        "mz": "$request_referer",
        "rules" :[
        {
            "id": "1001",
            "from": 0,
            "to": 10
        },
        {
            "id": "1002",
            "from": 0,
            "to": 10
        }
        ]
    }
}

## golang libs
+ 逻辑表达式计算:
    + govaluate : express compute
    + hyperscan 5.0 内置逻辑表达式
+ BODY:
    + 流式json解析： jsonparser gjson
    + xml解析
+ fasthttp: contain fasthttp goroutine pool
+ go-cache

## BufFix:

## golang 生成core文件
+ rule1:开启core文件： ulimit -c unlimited (-c 代表core) ,设置后可以通过ulimited -a看到, 可以通过程序设置
+ rule2: exoprt指令设置环境变量或执行时使用env指令设置： env GOTRACEBACK=crash ./testgotraceback  (注意GOTRACEBACK=all不能生成core文件)
+ 条件取决于程序启动时刻这两项参数，启动后再修改不生效;

## TODO
+ nginx内部sleep是否会block其他请求
+ nginx流量如何转发到waf
    + openresty ngx.location.capture http2 (是否支持http2)
+ 策略引擎实现？  hyper5 logic ？or evalueate
+ 实现逻辑引擎LogicEngine(govaluate)
+ 日志的时间不对
+ hyperscan 规则 flag优化
+ 性能优化： 目前开启WAF, 性能从7w下降到3w(白流量和黑流量一样)
+ policiers封装实现 valueate
+ 匹配域matcher实现： 每个匹配域对应一个pool，可以配置worker数量(也不行， matcher需要单例的scratch）
+ json config 解析 及 模块化
    + 移植 statbot mutl goroutine model
    + MainConfig module
    + RulesConfig : Match zone && regex && flag && logic
    + HSMatcher 模块化 
+ 实现规则引擎RuleEngine
+ matcher 前面增加流式函数插件处理, 以及开关(spider_ip_rdns/router)
+ 原文匹配支持
+ 解码匹配支持 $u__
+ 自适应匹配
+ 协程池tunny实现对同一个matcher的匹配
+ 异步：通过通道传递数据到matcher的多个协程
+ 高效性能设计： 请求头+ URI + BODY 高效匹配设计
    + 请求头并发匹配(避免嵌套循环，计算消耗会指数下降)
    + 请求BODY多协程匹配
+ body的读取tunny pool

## TODO2:
+ apisix + fastscaner
+ 黑名单功能
+ 白名单功能

## DONE
+ 解决多规则命中只打印一个规则问题
+ 配置文件说明: procnum等
+ 多match对输入数据包（URI、BODY、HEADER等）集中快速查找匹配问题
+ 支持变量： nginx原版变量
+ 并发处理： 函数调用方式（同步） &&  通道方式(异步)
+ 通道方式： 每个协程 +  一个通道 +  一个scratch
+ 一个数据包分发distworker对应多个scanworker对应 +  distworker :qa
+ 每个scanworker对一组matchers, 有多个scanworker
+ 守护进程实现
+ pid写入到文件， 防止启动多个
+ worker dev && test  [done]
+ logrus + file-rotatelogs
+ fasthttp + hyperscan 
+ hyperscan static lib 
+ nginx性能测试 并发 + 延迟
+ fasthttp性能测试 并发 + 延迟
+ nginx + (http socket | unix socket)  + fasthttp 延迟测试

## OTHER
+ tunny goroutine pool(无法实现对每个matcher传递对应的独立scratch)

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
    + 多个协程使用一个scratch会报错： ERROR: Unable to scan input buffer. Exiting. err: The scratch region was already in use.



## 配置 


## Note:
+ go build -gcflags=all="-N -l"  ## 必须这样编译，才能用gdb打印出变量，第二个是小写的L，不是大写的i
+ 流量转发到waf: 使用resty.http连接waf模块

