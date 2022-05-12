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

	/*
		cpuNum := runtime.NumCPU()
		runtime.GOMAXPROCS(runtime.NumCPU() -1 )
	*/

	var rlimit syscall.Rlimit

	// 限制cpu个数, 程序使用超过限制， 可能会导致程序被kill
	/*
		rlimit.Cur = 1
		rlimit.Max = cpu_max
		syscall.Setrlimit(syscall.RLIMIT_CPU, &rlimit)
		err := syscall.Getrlimit(syscall.RLIMIT_CPU, &rlimit)
		if err != nil {
			return err
		}
	*/

	//set core limit
	rlimit.Cur = 100 //以字节为单位
	rlimit.Max = rlimit.Cur + core_max
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &rlimit); err != nil {
		return err
	}
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &rlimit); err != nil {
		return err
	}

	//set nofile rlimit
	var rLimit syscall.Rlimit
	rLimit.Cur = 65535
	rLimit.Max = 65535
	err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		log.Fatal("err:", err.Error())
	}

	//set procs && cpu nums use
	if fastScanner.conf.CPUNum > 0 {
		runtime.GOMAXPROCS(int(fastScanner.conf.CPUNum))
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

}

//run in fasthttp goroutine
func request_handler(ctx *fasthttp.RequestCtx) {

	/*
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
	*/

	request_id := strconv.FormatUint(ctx.ID(), 10)
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

	var hitRes []scanner.HSContext
	for _, r := range res.([]scanner.HSContext) {
		if len(r.Results) == 0 {
			continue
		}
		hitRes = append(hitRes, r)
	}

	var hitResJson []byte
	if len(hitRes) > 0 {
		hitResJson, err = json.Marshal(hitRes)
		if err != nil {
			log.WithFields(log.Fields{"waf-request-id": request_id, "Error": err.Error()}).Error("Error:")
		}
	}

	status_code := 200
	ctx.Response.Header.Set("waf-request-id", request_id)
	if len(hitRes) > 0 {
		status_code = 403
		ctx.Response.Header.Set("anti-type", "secrule")
		ctx.Response.SetStatusCode(status_code)
		if isdev {
			if len(hitResJson) > 0 {
				ctx.Response.Header.Set("waf-hit-rules", string(hitResJson))
			}
		}
	}

	tmpStr := fmt.Sprintf("waf-request-id:%s status:%d", request_id, status_code)
	if len(hitResJson) > 0 {
		tmpStr = tmpStr + " waf-hit-rules:" + string(hitResJson)
	}

	log.Info(tmpStr)

	//Set Waf-Header
	ctx.SetContentType("text/plain; charset=utf8")

	/*
		// Set cookies
		var c fasthttp.Cookie
		c.SetKey("cookie-name")
		c.SetValue("cookie-value")
		ctx.Response.Header.SetCookie(&c)
	*/
}

type Conf struct {
	//Debug    bool   `json:"debug"`
	Version  string `json:"version"`
	LogLevel int    `json:"loglevel"`
	CPUNum   int    `json:"cpunum"`
	//ProcNum  int    `json:"procnum"`
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

	//Start Daemon
	if !isdev {
		//Daemon
		//判断当其是否是子进程，当父进程return之后，子进程会被 系统1 号进程接管
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

	//Check PID File
	exDir, err := os.Executable()
	if err != nil {
		log.Fatal("Error:", err.Error())
	}
	pathDir := filepath.Dir(exDir)
	once_pid, started := common.PidfileExit(pathDir + "/" + pidFile)
	if started {
		if once_pid > 0 {
			log.Error("exec already exist:", once_pid)
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

	if !isdev && fastScanner.conf.LogLevel > 0 {
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
