package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

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
)

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

	//通过通道传递数据到

	/*
		hsctx := HSContext{Data: ctx.RequestURI()}
		if err := hsMatcher.Match(&hsctx); err != nil {
			log.Error("Error:", err.Error())
		}

		if hsctx.Id > 0 {
			ctx.Response.Header.Set("waf-hit-id", strconv.Itoa(int(hsctx.Id)))
			ctx.Response.SetStatusCode(403)
		}
	*/

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
	Debug   bool   `json:"debug"`
	Version string `json:"version"`
	CPUNum  int    `json:"cpunum"`
	ProcNum int    `json:"procnum"`
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

	log.Info("Start server done!")

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

func main() {

	Testworker()
	time.Sleep(1 * time.Second)
	os.Exit(1)

	log.Info("Starting ...")

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
	log.Info("version:", fastScanner.conf.Version)

	//============= MODULE ===============
	ins, err := scanner.NewScanner(confData, &mctx, nil)
	if err != nil {
		log.Fatal("init scanner.NewScanner error!")
	}
	ins.Start()

	go ServeStart(&mctx)

	//============= MODULE ===============

	//wait for exit signal
	<-sigCh

	//module clean
	ins.Stop()

	//main clean
	cancel()
	log.Warn("Stop done!")
}
