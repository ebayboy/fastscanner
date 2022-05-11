package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Jeffail/tunny"
	"github.com/fastscanner/common"
	"github.com/fastscanner/scanner"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

var (
	isdev    bool
	version  bool
	logFile  string
	confFile string
	addr     string
	pidFile  string = "fastscanner.pid"
)

func initSetLimit(cpu_max uint64, core_max uint64) error {
	var rlimit syscall.Rlimit

	// 限制cpu个数
	rlimit.Cur = 1
	rlimit.Max = cpu_max
	syscall.Setrlimit(syscall.RLIMIT_CPU, &rlimit)
	err := syscall.Getrlimit(syscall.RLIMIT_CPU, &rlimit)
	if err != nil {
		return err
	}

	//set core limit
	rlimit.Cur = 100 //以字节为单位
	rlimit.Max = rlimit.Cur + core_max
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &rlimit); err != nil {
		return err
	}
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &rlimit); err != nil {
		return err
	}

	return nil
}

func init() {

	//parse flag
	flag.BoolVar(&isdev, "d", false, "run in dev mode")
	flag.BoolVar(&version, "version", false, "output version info")
	flag.StringVar(&logFile, "log", "./logs/fastscanner.log", "error.log")
	flag.StringVar(&confFile, "conf", "./conf/config.json", "config file")
	flag.StringVar(&addr, "addr", ":9999", "TCP address to listen to")
	flag.Parse()

	//log init
	log.SetFormatter(&log.TextFormatter{
		DisableColors:   true,
		TimestampFormat: "1970-00-00 00:00:00",
	})

	// Start flag: -d
	if isdev {
		log.SetOutput(os.Stdout)
		log.SetLevel(log.DebugLevel)
	} else {
		logPath := logFile
		rtt_writer, _ := rotatelogs.New(
			logPath+".%Y%m%d%H%M",
			rotatelogs.WithLinkName(logFile),
			rotatelogs.WithMaxAge(72*time.Hour),
			rotatelogs.WithRotationTime(24*time.Hour),
		)

		log.SetFormatter(&log.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
		log.SetOutput(rtt_writer)
		log.SetLevel(log.InfoLevel)
	}

	//set rlimit
	var rLimit syscall.Rlimit
	rLimit.Cur = 65535
	rLimit.Max = 65535
	err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		log.Fatal("err:", err.Error())
	}

	//set procs
	runtime.GOMAXPROCS(int(fastScanner.conf.CPUNum))
}

//run in fasthttp goroutine
func request_handler(ctx *fasthttp.RequestCtx) {

	fmt.Fprintf(ctx, "Hello, world!\n\n")
	fmt.Fprintf(ctx, "Request method is %q\n", ctx.Method())
	fmt.Fprintf(ctx, "RequestURI is %q\n", ctx.RequestURI())
	fmt.Fprintf(ctx, "Requested path is %q\n", ctx.Path())
	fmt.Fprintf(ctx, "Host is %q\n", ctx.Host())
	fmt.Fprintf(ctx, "Query string is %q\n", ctx.QueryArgs())
	fmt.Fprintf(ctx, "User-Agent is %q\n", ctx.UserAgent())
	fmt.Fprintf(ctx, "Connection has been established at %s\n", ctx.ConnTime())
	fmt.Fprintf(ctx, "Request has been started at %s\n", ctx.Time())
	fmt.Fprintf(ctx, "Serial request number for the current connection is %d\n", ctx.ConnRequestNum())
	fmt.Fprintf(ctx, "Your ip is %q\n\n", ctx.RemoteIP())
	fmt.Fprintf(ctx, "Raw request is:\n---CUT---\n%s\n---CUT---", &ctx.Request)

	distCtx := scanner.DistWorkerContext{DistWorker: distWorker}
	distCtx.Data = make(map[string][]byte)

	if len(ctx.Method()) > 0 {
		distCtx.Data["request_method"] = ctx.Method()
	}
	if len(ctx.RequestURI()) > 0 {
		distCtx.Data["request_uri"] = ctx.RequestURI()
	}
	if len(ctx.Referer()) > 0 {
		distCtx.Data["http_referer"] = ctx.Referer()
	}
	if len(ctx.UserAgent()) > 0 {
		distCtx.Data["http_user_agent"] = ctx.UserAgent()
	}
	if len(ctx.PostBody()) > 0 {
		distCtx.Data["request_body"] = ctx.PostBody()
	}

	//性能优化：
	// + 不走匹配流程： Requests/sec: 73028.06
	// + 走匹配流量: Requests/sec:  23948.57
	// + 走匹配不打日志: Requests/sec:  32835.78
	res, err := distWorker.Pool.ProcessTimed(&distCtx, time.Second*5)
	if err == tunny.ErrJobTimedOut {
		log.WithFields(log.Fields{"hsCtx": distCtx, "rerr": err.Error()}).Error("Error: Request timed out!")
		return
	}

	scanner.HSContextsShow(res.([]scanner.HSContext))

	var hit_ids []string
	var hit_payloads []string
	for _, hsctx := range res.([]scanner.HSContext) {
		if hsctx.Id == 0 {
			continue
		}
		rule_id := strconv.Itoa(int(hsctx.Id))
		if err != nil {
			log.Error("Error: strconv.Atoi:", hsctx.Id)
			continue
		}
		hit_ids = append(hit_ids, rule_id)
		hit_payloads = append(hit_payloads, string(hsctx.Data[hsctx.From:hsctx.To]))
	}

	request_id := strconv.FormatUint(ctx.ID(), 10)
	log.WithFields(log.Fields{"hit_ids": hit_ids, "hit_payloads": hit_payloads, "request_id": request_id}).Info("Res") //影响1.7w QPS

	if len(hit_ids) > 0 {
		ctx.Response.Header.Set("waf-request-id", request_id)
		ctx.Response.Header.Set("waf-hit-ids", strings.Join(hit_ids, ","))
		ctx.Response.Header.Set("waf-hit-payloads", strings.Join(hit_payloads, ","))
		ctx.Response.SetStatusCode(403)
	}

	ctx.SetContentType("text/plain; charset=utf8")

	// Set arbitrary headers
	ctx.Response.Header.Set("X-My-Header", "my-header-value")

	// Set cookies
	var c fasthttp.Cookie
	c.SetKey("cookie-name")
	c.SetValue("cookie-value")
	ctx.Response.Header.SetCookie(&c)
}

type Conf struct {
	Debug    bool   `json:"debug"`
	Version  string `json:"version"`
	LogLevel int    `json:"loglevel"`
	CPUNum   int    `json:"cpunum"`
	ProcNum  int    `json:"procnum"`
}

type FastScanner struct {
	confFile string
	conf     Conf
}

func ServeStart(mctx *context.Context) {

	//start server
	go func() {
		h := request_handler
		if err := fasthttp.ListenAndServe(addr, h); err != nil {
			log.WithField("err", err.Error()).Fatal("Error: fasthttp.ListenAndServe")
		}
	}()

	log.Info("Start server done! Listen on:", addr)

	//exit before main exit
	for {
		select {
		case <-(*mctx).Done():
			log.Debug("Recv mctx Done...")
		default:
			time.Sleep(time.Second)
		}
	}
}

var fastScanner FastScanner
var distWorker *scanner.DistWorker

func main() {

	//init  cpu && core limit
	if err := initSetLimit(2, 2*1024*1024); err != nil {
		log.Error("Error:", err.Error())
	}

	//启动dev模式
	if !isdev {
		fmt.Println("Start with daemon...")
		//Start daemon
		//判 断当其是否是子进程，当父进程return之后，子进程会被 系统1 号进程接管
		if os.Getppid() != 1 {
			// 将命令行参数中执行文件路径转换成可用路径
			filePath, _ := filepath.Abs(os.Args[0])
			cmd := exec.Command(filePath, os.Args[1:]...)
			// 将其他命令传入生成出的进程
			cmd.Stdin = os.Stdin // 给新进程设置文件描述符，可以重定向到文件中
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Start() // 开始执行新进程，不等待新进程退出
			return
		}
	}

	//check pid exist
	exDir, err := os.Executable()
	if err != nil {
		log.Fatal("Error:", err.Error())
	}
	pathDir := filepath.Dir(exDir)
	once_pid, started := common.PidfileExit(pathDir + "/" + pidFile)
	if started {
		if once_pid > 0 {
			log.Error("exec already exist:%d\n", once_pid)
			return
		}
	} else {
		if once_pid > 0 {
			log.Info("start new proc:%d", once_pid)
			//HandleSingle()  //信号处理
			defer os.Remove(pidFile) //程序退出后删除pid文件
		}
	}

	//Start process
	log.Info("Starting ... pid:", once_pid)

	//init ctx && signal
	mctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	//read Main Conf
	confData, err := ioutil.ReadFile(confFile)
	if err != nil {
		log.Fatal("Read conf error!")
	}

	if err := json.Unmarshal(confData, &fastScanner.conf); err != nil {
		log.Fatal("Parse main conf error!")
	}

	if fastScanner.conf.LogLevel > 0 {
		log.SetLevel(log.Level(fastScanner.conf.LogLevel))
		log.Info("Reset loglevel to:", fastScanner.conf.LogLevel)
	}

	log.WithFields(log.Fields{"version": fastScanner.conf.Version, "LogLevel": fastScanner.conf.LogLevel}).Info()

	distWorker, err = scanner.NewDistWorker(1, confData, &mctx, nil)
	if err != nil {
		log.Fatalln("Error: scanner.NewDistWorker! err:", err.Error())
	}

	go ServeStart(&mctx)

	//============= MODULE ===============

	//wait for exit signal
	<-sigCh

	//module clean

	//main clean
	cancel()
	log.Warn("Stop done!")
}
